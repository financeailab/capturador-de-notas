#!/usr/bin/env python3
"""Cheque saida sem dado: AST fail-closed sobre o que um motor pode imprimir.

Uso: python checar_saida_sem_dado.py <pasta>

Regra (docs/decisions/saida-sem-dado.md no monorepo financeailab): o que o agente le do motor
(stdout, stderr, relatorio) nunca leva texto do arquivo da pessoa. Varre todo .py e todo
pyproject.toml/setup.cfg sob <pasta>, menos teste (pasta tests/, test_*.py, conftest.py).

Reprova (uma linha "arquivo:linha: regra motivo" por achado, sem ecoar o codigo):
- R1: dentro de `except ... as <nome>`, uso de <nome> fora de: `raise <nome>`, `raise X from <nome>`,
  <nome> dentro de `raise X(...)` (o texto segue como excecao; quem o imprime e marcado onde
  imprime, e R3 garante o topo), `isinstance(<nome>, ...)`, `type(<nome>)`, `<nome>.__class__`,
  `<nome>.errno`, `<nome>.strerror` (texto do sistema operacional). `raise SystemExit(...)` e
  `sys.exit(...)` com <nome> dentro reprovam (o Python imprime a mensagem).
- R1: `SystemExit(...)`/`sys.exit(...)` com texto formatado (f-string, %, +, .format, str()).
- R2: traceback.* (inclusive alias e `from traceback import`), `.exception` de qualquer logger,
  argumento exc_info, sys.exception() e sys.exc_info() (inclusive alias e `from sys import`), import de
  threading, _thread, atexit e multiprocessing (excecao la imprime traceback fora do template).
- R3: ponto de entrada diferente do template `_TEMPLATE_MAIN` abaixo. O unico ponto de entrada
  aceito e esse bloco, identico na arvore sintatica (comentario e linha em branco nao contam), como
  ultima instrucao do modulo. Reprova: comparacao com `__name__` fora dele (qualquer operador, ordem
  e profundidade), chamada de `main` no nivel do modulo fora dele, __main__.py sem ele e, em todo
  .py, instrucao de topo ou de corpo de classe que executa algo (fora do template, so import, def,
  class, atribuicao, docstring, sys.path.*, try de import opcional e if com corpo assim). Unica outra
  entrada aceita: o bloco de instalacao do guarda (`_TEMPLATE_GUARDA`), uma vez, no nivel do modulo. O template
  pega tudo (BaseException), so escreve texto fixo e sai com codigo inteiro fora do handler, e cala a
  excecao nao levantavel (`__del__`, finalizador): nenhum texto de excecao, de SystemExit ou de
  retorno de main() chega a saida.
  Limite: expressao avaliada na definicao (valor de atribuicao, teste de if, default de parametro,
  decorador, base de classe) roda antes do template; o teste-canario de cada motor cobre esse caminho.
- R3: pyproject.toml que declara executavel (project.scripts, project.gui-scripts, tool.poetry.scripts,
  em qualquer forma de TOML) ou setup.cfg com console_scripts/gui_scripts em [options.entry_points]:
  ponto de entrada fora do template nao e suportado.
- Erro de parse (inclusive de pyproject.toml e setup.cfg).
Pasta inexistente ou sem .py: exit 2.

Escape (so R1): comentario `# saida-ok: <motivo>` na linha do achado, motivo nao vazio, lido por
tokenize (texto dentro de string nao vale). Todo escape aparece na saida, com regra e motivo,
para a revisao conferir. R2 e R3 nao tem escape.
"""
from __future__ import annotations

import ast
import configparser
import io
import re
import sys
import tokenize
import tomllib
from pathlib import Path

_ESCAPE = re.compile(r"#\s*saida-ok:\s*(\S.*)$")
_ATRIBUTOS_OK = {"__class__", "errno", "strerror"}
_SYS_EXCECAO = {"exception", "exc_info"}
_CANAIS_FORA = {"threading", "_thread", "atexit", "multiprocessing"}
R1, R2, R3 = "R1", "R2", "R3"
_MSG_R3 = "ponto de entrada fora do template _TEMPLATE_MAIN de checar_saida_sem_dado.py"

# Copie este bloco literal para o fim do script do motor (main() sem argumento, devolvendo int).
_TEMPLATE_MAIN = r'''
if __name__ == "__main__":
    import sys as _sys
    _sys.unraisablehook = lambda _u: None
    _codigo = 2
    try:
        _codigo = main()
    except SystemExit as _e:
        _codigo = _e.code
    except BaseException:
        try:
            _sys.stderr.write("erro inesperado; o detalhe nao e impresso para nao expor o arquivo\n")
        except BaseException:
            pass
    raise SystemExit(_codigo if _codigo.__class__ is int else (0 if _codigo is None else 2))
'''
_DUMP_MAIN = ast.dump(ast.parse(_TEMPLATE_MAIN).body[0])

# Bloco de instalacao do guarda em tempo de execucao do capturador: o unico outro teste de `__name__` aceito,
# uma vez so, no nivel do modulo, logo depois do `from engine import guarda` (os dois identicos a estes); a posicao
# no programa (antes de todo import de terceiro) e do checar_sem_rede.py, que so vale para o capturador.
_TEMPLATE_GUARDA = r'''
from engine import guarda

if __name__ == "__main__":
    guarda.instalar(Path(__file__).resolve())
'''
_DUMP_GUARDA = tuple(ast.dump(s) for s in ast.parse(_TEMPLATE_GUARDA).body)


def _escapes(fonte: str) -> dict[int, str]:
    motivos = {}
    for tok in tokenize.generate_tokens(io.StringIO(fonte).readline):
        if tok.type == tokenize.COMMENT:
            m = _ESCAPE.search(tok.string)
            if m:
                motivos[tok.start[0]] = m.group(1).strip()
    return motivos


def _nome(no, *nomes) -> bool:
    return isinstance(no, ast.Name) and no.id in nomes


def _eh_exit(func) -> bool:
    return _nome(func, "SystemExit") or (
        isinstance(func, ast.Attribute) and func.attr == "exit" and _nome(func.value, "sys"))


def _texto_formatado(no) -> bool:
    if isinstance(no, (ast.JoinedStr, ast.BinOp)):
        return True
    if isinstance(no, ast.Call):
        f = no.func
        return _nome(f, "str", "repr", "format") or (isinstance(f, ast.Attribute) and f.attr == "format")
    return False


def _usos_permitidos(handler: ast.ExceptHandler) -> set[int]:
    ok: set[int] = set()
    for no in ast.walk(ast.Module(body=handler.body, type_ignores=[])):
        if isinstance(no, ast.Raise):
            exc_ok = no.exc is not None and not (isinstance(no.exc, ast.Call) and _eh_exit(no.exc.func)) \
                and not _nome(no.exc, "SystemExit")
            if exc_ok:
                ok.update(id(n) for n in ast.walk(no.exc) if isinstance(n, ast.Name))
            if no.cause is not None:
                ok.update(id(n) for n in ast.walk(no.cause) if isinstance(n, ast.Name))
        elif isinstance(no, ast.Call) and _nome(no.func, "isinstance", "type") and no.args and isinstance(no.args[0], ast.Name):
            ok.add(id(no.args[0]))
        elif isinstance(no, ast.Attribute) and no.attr in _ATRIBUTOS_OK and isinstance(no.value, ast.Name):
            ok.add(id(no.value))
    return ok


def _r1(arvore) -> list[tuple[int, str, str]]:
    achados = []
    for no in ast.walk(arvore):
        if isinstance(no, ast.ExceptHandler) and no.name:
            ok = _usos_permitidos(no)
            for stmt in no.body:
                for n in ast.walk(stmt):
                    if isinstance(n, ast.Name) and n.id == no.name and isinstance(n.ctx, ast.Load) and id(n) not in ok:
                        achados.append((n.lineno, R1, f"texto da excecao '{no.name}' pode ir para a saida"))
        elif isinstance(no, ast.Call) and _eh_exit(no.func) and no.args and _texto_formatado(no.args[0]):
            achados.append((no.lineno, R1, "SystemExit com texto formatado (o Python imprime no stderr)"))
    return achados


def _r2(arvore) -> list[tuple[int, str, str]]:
    achados = []
    nomes_tb, nomes_sys = {"traceback"}, {"sys"}
    for no in ast.walk(arvore):
        if isinstance(no, ast.Import):
            nomes_tb.update(a.asname for a in no.names if a.name == "traceback" and a.asname)
            nomes_sys.update(a.asname for a in no.names if a.name == "sys" and a.asname)
            achados += [(no.lineno, R2, "thread/atexit/processo (a excecao la imprime traceback fora do template)")
                        for a in no.names if a.name.split(".")[0] in _CANAIS_FORA]
        elif isinstance(no, ast.ImportFrom) and no.module == "traceback":
            achados.append((no.lineno, R2, "import de traceback (imprime a excecao inteira)"))
        elif isinstance(no, ast.ImportFrom) and (no.module or "").split(".")[0] in _CANAIS_FORA:
            achados.append((no.lineno, R2, "thread/atexit/processo (a excecao la imprime traceback fora do template)"))
        elif isinstance(no, ast.ImportFrom) and no.module == "sys" and any(a.name in _SYS_EXCECAO for a in no.names):
            achados.append((no.lineno, R2, "excecao ativa lida de sys (sys.exception/sys.exc_info)"))
    for no in ast.walk(arvore):
        if isinstance(no, ast.Attribute):
            nome = no.value.id if isinstance(no.value, ast.Name) else None
            if nome in nomes_tb:
                achados.append((no.lineno, R2, f"uso de traceback.{no.attr} (imprime a excecao inteira)"))
            elif nome in nomes_sys and no.attr in _SYS_EXCECAO:
                achados.append((no.lineno, R2, f"sys.{no.attr} (excecao ativa sem nome)"))
            elif no.attr == "exception":  # qualquer logger (getLogger em variavel, self.log): imprime o traceback
                achados.append((no.lineno, R2, ".exception de logger (imprime a excecao inteira)"))
        elif isinstance(no, ast.keyword) and no.arg == "exc_info":
            achados.append((no.value.lineno, R2, "exc_info (imprime a excecao inteira)"))
    return achados


def _testa_main(no) -> bool:
    """Qualquer comparacao com `__name__` (==, in, invertida)."""
    lados = [no.left, *no.comparators] if isinstance(no, ast.Compare) else []
    return any(_nome(x, "__name__") for x in lados)


def _topo_permitido(s) -> bool:
    """Instrucao de topo que so define coisas: import, def, class (com corpo assim), atribuicao, docstring,
    sys.path.*, import opcional (try so com import/atribuicao) e if com corpo assim. Expressao avaliada na
    definicao e o limite declarado no docstring do modulo."""
    if isinstance(s, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.AsyncFunctionDef,
                      ast.Assign, ast.AnnAssign, ast.Pass)):
        return True
    if isinstance(s, ast.ClassDef):  # o corpo da classe roda na definicao
        return all(_topo_permitido(x) for x in s.body)
    if isinstance(s, ast.Expr):
        v, f = s.value, getattr(s.value, "func", None)
        return (isinstance(v, ast.Constant) and isinstance(v.value, str)) or (
            isinstance(f, ast.Attribute) and isinstance(f.value, ast.Attribute) and f.value.attr == "path" and _nome(f.value.value, "sys"))
    if isinstance(s, ast.Try):
        corpo = s.body + s.orelse + [x for h in s.handlers for x in h.body]
        return not s.finalbody and all(isinstance(x, (ast.Import, ast.ImportFrom, ast.Assign, ast.Pass)) for x in corpo)
    if isinstance(s, ast.If):  # `if TYPE_CHECKING:`, `if X not in sys.path:` - corpo so com definicao
        return all(_topo_permitido(x) for x in s.body + s.orelse)
    return False


def _r3(arvore, caminho: Path) -> tuple[list[tuple[int, str, str]], tuple[int, int] | None]:
    """Devolve (achados, faixa de linhas do template) - a faixa fica fora do R1 (o `_e.code` dele e seguro)."""
    fim = arvore.body[-1] if arvore.body else None
    faixa = (fim.lineno, fim.end_lineno) if isinstance(fim, ast.If) and ast.dump(fim) == _DUMP_MAIN else None
    pares = [i for i in range(len(arvore.body) - 1)
             if tuple(ast.dump(s) for s in arvore.body[i:i + 2]) == _DUMP_GUARDA]
    guarda = arvore.body[pares[0] + 1] if len(pares) == 1 else None
    faixas = [f for f in (faixa, guarda and (guarda.lineno, guarda.end_lineno)) if f]
    dentro = lambda n: any(a <= n.lineno <= b for a, b in faixas)
    achados = [(n.lineno, R3, _MSG_R3) for n in ast.walk(arvore) if _testa_main(n) and not dentro(n)]
    for stmt in arvore.body:
        if dentro(stmt) or (isinstance(stmt, ast.If) and _testa_main(stmt.test)):
            continue  # o template, ou bloco __main__ fora dele (ja saiu acima, uma vez so)
        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            achados += [(n.lineno, R3, _MSG_R3) for n in ast.walk(stmt) if isinstance(n, ast.Call) and _nome(n.func, "main")]
        if not _topo_permitido(stmt):
            achados.append((stmt.lineno, R3, "execucao no topo do modulo fora do template (so import, def, class, atribuicao)"))
    if caminho.name == "__main__.py" and faixa is None:
        achados.append((1, R3, _MSG_R3))
    return achados, faixa


def _entry_point(caminho: Path, fonte: str) -> list[tuple[int, str, str]]:
    """Executavel declarado em pyproject.toml/setup.cfg roda main() fora do template."""
    try:
        if caminho.name == "pyproject.toml":
            d = tomllib.loads(fonte)
            achou = bool({"scripts", "gui-scripts"} & set(d.get("project", {}))) \
                or "scripts" in d.get("tool", {}).get("poetry", {})
        else:
            cfg = configparser.ConfigParser(interpolation=None)
            cfg.read_string(fonte)
            achou = cfg.has_section("options.entry_points") \
                and bool({"console_scripts", "gui_scripts"} & set(cfg["options.entry_points"]))
    except Exception:  # invalido ou com tipo inesperado: fail-closed
        return [(1, "parse", "erro de parse")]
    return [(1, R3, "entry point declarado fora do template")] if achou else []


def checar_arquivo(caminho: Path) -> tuple[list[tuple[int, str, str]], list[tuple[int, str, str]]]:
    """Devolve (achados, escapes), cada item (linha, regra, motivo)."""
    fonte = caminho.read_text(encoding="utf-8")
    if caminho.suffix != ".py":
        return _entry_point(caminho, fonte), []
    try:
        arvore = ast.parse(fonte, filename=str(caminho))
    except SyntaxError as e:
        return [(e.lineno or 1, "parse", "erro de parse")], []
    motivos = _escapes(fonte)
    achados_r3, faixa = _r3(arvore, caminho)
    r1 = [a for a in _r1(arvore) if faixa is None or not faixa[0] <= a[0] <= faixa[1]]
    achados, escapes = [], []
    for linha, regra, motivo in sorted(set(r1 + _r2(arvore) + achados_r3)):
        if regra == R1 and linha in motivos:
            escapes.append((linha, regra, motivos[linha]))
        else:
            achados.append((linha, regra, motivo))
    return achados, escapes


def _eh_teste(rel: Path) -> bool:
    return "tests" in rel.parts[:-1] or rel.name.startswith("test_") or rel.name == "conftest.py"


def _encontrar_arquivos(pasta: Path) -> list[Path]:
    todos = sorted(p for padrao in ("*.py", "pyproject.toml", "setup.cfg") for p in pasta.rglob(padrao))
    return [p for p in todos if not _eh_teste(p.relative_to(pasta))]


def main(argv) -> int:
    if len(argv) != 2:
        print("uso: checar_saida_sem_dado.py <pasta>", file=sys.stderr)
        return 2
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # consoles cp1252 do Windows nao tem U+2713
    pasta = Path(argv[1])
    arquivos = _encontrar_arquivos(pasta) if pasta.is_dir() else []
    if not any(p.suffix == ".py" for p in arquivos):
        print(f"nenhum .py em {pasta}", file=sys.stderr)
        return 2
    total = n_escapes = 0
    for caminho in arquivos:
        achados, escapes = checar_arquivo(caminho)
        for linha, regra, motivo in achados:
            print(f"{caminho}:{linha}: {regra} {motivo}")
        for linha, regra, motivo in escapes:
            print(f"{caminho}:{linha}: escape {regra}: {motivo}")
        total += len(achados)
        n_escapes += len(escapes)
    if total:
        return 1
    n_py = sum(p.suffix == ".py" for p in arquivos)
    print(f"✓ saida sem dado: {n_py} arquivos, {n_escapes} escape(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
