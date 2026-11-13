#!/usr/bin/env python3
"""Cheque sem rede: AST fail-closed por lista fechada de imports permitidos.

Uso: python checar_sem_rede.py <pasta> [--ferramenta <programa>]

Modo --ferramenta <programa> (layout raiz, hoje so capturador-de-notas): varre so capturador.py e
engine/**/*.py de <pasta>, com a lista propria de "programas" em imports-permitidos.json (a lista
global de stdlib nao cresce) e excecoes por CAMINHO relativo a <pasta> (ver checar_programa).

Varre <pasta>/**/skills/<nome>/scripts/**/*.py; cada diretorio skills/<nome>/scripts
usa a allowlist do plugin <nome> (stdlib + terceiros + internos declarados em
imports-permitidos.json). Se <pasta> nao contiver nenhum diretorio nesse formato,
trata <pasta> como uma pasta de scripts de motor (uso direto nos motores do
monorepo) e varre todo .py sob ela usando a uniao das allowlists de todos os plugins.

Reprova (uma linha por achado, "arquivo:linha: motivo"):
- erro de parse;
- import (estatico, em qualquer nivel, inclusive dentro de funcao) de modulo cujo
  nome de topo nao esteja na allowlist aplicavel (import relativo do proprio
  pacote e sempre permitido);
- chamada a __import__, exec, eval, compile, qualquer atributo de importlib,
  os.system, os.popen, os.exec*, os.spawn*, os.posix_spawn* (inclusive via
  "from os import system" etc., mesmo sem chamada).

Excecao: import de modulo listado em "excecoes" do JSON, casado por nome de
arquivo, nome do modulo e (quando declarada) nome da funcao que envolve o
no (hoje: "import gspread" dentro de "push_para_sheet" em sheets_push.py;
fora dessa funcao, no topo do arquivo ou em outra funcao, reprova).
"""
from __future__ import annotations

import ast
import builtins
import copy
import json
import re
import sys
from pathlib import Path

CONFIG_PATH = Path(__file__).parent / "imports-permitidos.json"

_OS_FORBIDDEN_PREFIXES = ("exec", "spawn", "posix_spawn")
_OS_FORBIDDEN_EXACT = {"system", "popen", "startfile"}
_BUILTIN_FORBIDDEN = {"__import__", "exec", "eval", "compile"}


def carregar_config(path: Path = CONFIG_PATH) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _allowlist_para_plugin(config: dict, nome_plugin):
    permitidos = set(config["stdlib"])
    plugins = config["plugins"]
    alvo = [plugins[nome_plugin]] if nome_plugin in plugins else plugins.values()
    for p in alvo:
        permitidos.update(p.get("terceiros", []))
        permitidos.update(p.get("internos", []))
    return permitidos


def _excecao_permite(config: dict, arquivo: Path, nome_modulo: str, funcao_atual) -> bool:
    for exc in config.get("excecoes", []):
        if arquivo.name != exc["arquivo"] or nome_modulo != exc["import"]:
            continue
        if "funcao" in exc and exc["funcao"] != funcao_atual:
            continue  # mesmo import, fora da funcao declarada: nao e excecao
        return True
    return False


def _dump(no) -> str:
    """ast.dump estavel entre versoes: o 3.13+ omite campos vazios por padrao; as formas registradas os tem."""
    return ast.dump(no, include_attributes=False, **({"show_empty": True} if sys.version_info >= (3, 13) else {}))


def _os_forbidden(attr: str) -> bool:
    return attr in _OS_FORBIDDEN_EXACT or attr.startswith(_OS_FORBIDDEN_PREFIXES)


class _Visitor(ast.NodeVisitor):
    """Anda a arvore rastreando a funcao que envolve cada no (para a excecao
    por funcao) e coleta os achados."""

    def __init__(self, caminho: Path, allowlist: set, config: dict, excecao_caminho: dict | None = None,
                 programa: bool = False):
        self.caminho = caminho
        self.allowlist = allowlist
        self.config = config
        self.programa = programa
        # modo programa: excecoes do arquivo (por caminho relativo) e ids dos nos do topo do modulo
        self.exc_caminho = excecao_caminho
        self.topo_ids: set[int] = set()
        self._subprocess_ok: set[int] = set()  # ids do Name 'subprocess' da unica chamada registrada
        self.chamadas_ok = 0
        self.ids_funcao_registrada: set[int] = set()  # nos da UNICA funcao do topo com o nome registrado
        self.achados: list[tuple[int, str]] = []
        self._pilha_funcoes: list[str] = []
        self._os_nomes = {"os"}  # nomes que apontam para o modulo os ("import os as s")
        self._os_proibidos: set[str] = set()  # nomes locais de API proibida ("from os import system as f")
        self._alvos_gravacao = {"sys", "Path", "subprocess"}  # modo programa: nao se grava atributo neles

    def coletar_nomes_de_os(self, arvore) -> None:
        """1a passada: aliases de os e nomes proibidos importados de os no modulo
        inteiro, para que um import depois da funcao que o usa tambem conte."""
        for no in ast.walk(arvore):
            if isinstance(no, ast.Import):
                for alias in no.names:
                    if alias.name == "os" and alias.asname:
                        self._os_nomes.add(alias.asname)
                    if alias.name == "sys" and alias.asname:
                        self._alvos_gravacao.add(alias.asname)
            elif isinstance(no, ast.ImportFrom) and not no.level and no.module == "os":
                for alias in no.names:
                    if _os_forbidden(alias.name):
                        self._os_proibidos.add(alias.asname or alias.name)

    def _funcao_atual(self):
        return self._pilha_funcoes[-1] if self._pilha_funcoes else None

    def _excecao(self, nome_modulo: str) -> bool:
        if self.programa:
            return False  # modo programa: so excecoes_caminho; as globais sao dos plugins (Gate 1B, passe 1)
        return _excecao_permite(self.config, self.caminho, nome_modulo, self._funcao_atual())

    def visit_FunctionDef(self, node):
        self._pilha_funcoes.append(node.name)
        self.generic_visit(node)
        self._pilha_funcoes.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Import(self, node):
        for alias in node.names:
            topo = alias.name.split(".")[0]
            if topo not in self.allowlist and not self._excecao(topo) and not self._excecao_topo(node, alias):
                self.achados.append((node.lineno, f"import '{alias.name}' fora da allowlist"))
        self.generic_visit(node)

    def _excecao_topo(self, node, alias) -> bool:
        """Excecao por caminho: `import <nome>` puro, no topo do modulo, com o nome em imports_topo."""
        if not self.exc_caminho or id(node) not in self.topo_ids or alias.asname:
            return False
        return alias.name in self.exc_caminho.get("imports_topo", [])

    def visit_ImportFrom(self, node):
        if node.level and node.level > 0:
            self.generic_visit(node)
            return  # import relativo do proprio pacote: sempre permitido
        topo = (node.module or "").split(".")[0]
        if topo == "os":
            for alias in node.names:
                if alias.name == "*" or _os_forbidden(alias.name):
                    self.achados.append(
                        (node.lineno, f"'from os import {alias.name}': chamada proibida")
                    )
        if topo not in self.allowlist and not self._excecao(topo):
            self.achados.append((node.lineno, f"import '{topo}' fora da allowlist"))
        self.generic_visit(node)

    def visit_Call(self, node):
        func = node.func
        if (
            self.exc_caminho
            and "chamada_subprocess" in self.exc_caminho
            and isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "subprocess"
            and self._funcao_atual() == self.exc_caminho["funcao"]
            and id(node) in self.ids_funcao_registrada
            and _dump(node) == self.exc_caminho["chamada_subprocess"]
        ):
            self.chamadas_ok += 1
            self._subprocess_ok.add(id(func.value))
        if isinstance(func, ast.Name) and func.id in _BUILTIN_FORBIDDEN:
            self.achados.append((node.lineno, f"chamada proibida '{func.id}'"))
        elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            base = func.value.id
            if base == "importlib":
                self.achados.append((node.lineno, f"chamada proibida 'importlib.{func.attr}'"))
        self.generic_visit(node)

    def visit_Attribute(self, node):
        if self.programa:
            if (
                isinstance(node.ctx, (ast.Store, ast.Del))
                and isinstance(node.value, ast.Name)
                and node.value.id in self._alvos_gravacao
                and node.attr != "unraisablehook"
            ):
                self.achados.append((node.lineno, f"gravacao em '{node.value.id}.{node.attr}' no modo programa"))
        # pega chamada e simples referencia (f = os.system), inclusive via alias
        if (
            isinstance(node.value, ast.Name)
            and node.value.id in self._os_nomes
            and _os_forbidden(node.attr)
        ):
            self.achados.append((node.lineno, f"uso proibido 'os.{node.attr}'"))
        self.generic_visit(node)

    def visit_Name(self, node):
        if self.exc_caminho and node.id == "subprocess" and id(node) not in self._subprocess_ok:
            self.achados.append((node.lineno, "uso de 'subprocess' fora da unica chamada registrada"))
        # uso do nome local de "from os import system [as f]", em qualquer ordem
        if node.id in self._os_proibidos:
            self.achados.append((node.lineno, f"uso proibido '{node.id}' (importado de os)"))


def checar_arquivo(caminho: Path, allowlist: set, config: dict, excecao_caminho: dict | None = None,
                   programa: bool = False):
    """Retorna lista de (linha, motivo) para um arquivo. `excecao_caminho` e `programa` so no modo programa."""
    try:
        arvore = ast.parse(caminho.read_text(encoding="utf-8"), filename=str(caminho))
    except SyntaxError as e:
        return [(e.lineno or 1, f"erro de parse: {e.msg}")]

    visitor = _Visitor(caminho, allowlist, config, excecao_caminho, programa)
    visitor.topo_ids = {id(n) for n in arvore.body}
    if excecao_caminho and "chamada_subprocess" in excecao_caminho:
        fs = [n for n in arvore.body if isinstance(n, ast.FunctionDef) and n.name == excecao_caminho["funcao"]]
        if len(fs) == 1:
            visitor.ids_funcao_registrada = {id(n) for n in ast.walk(fs[0])}
    visitor.coletar_nomes_de_os(arvore)
    visitor.visit(arvore)
    achados = visitor.achados
    if excecao_caminho and "chamada_subprocess" in excecao_caminho:
        achados = achados + _checar_chamada_registrada(arvore, visitor, excecao_caminho)
    return achados


def _vinculos(no, nome: str) -> list:
    """Todo no de `no` que liga `nome` (atribuicao, import, def, except, argumento, match, global)."""
    achados = []
    for n in ast.walk(no):
        if isinstance(n, ast.Name):
            ligado = n.id == nome and isinstance(n.ctx, (ast.Store, ast.Del))
        elif isinstance(n, ast.alias):
            ligado = (n.asname or n.name.split(".")[0]) == nome
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.ExceptHandler)):
            ligado = n.name == nome
        elif isinstance(n, ast.arg):
            ligado = n.arg == nome
        elif isinstance(n, (ast.MatchAs, ast.MatchStar)):
            ligado = n.name == nome
        elif isinstance(n, ast.MatchMapping):
            ligado = n.rest == nome
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            ligado = nome in n.names
        else:
            ligado = False
        if ligado:
            achados.append(n)
    return achados


def _checar_chamada_registrada(arvore, visitor, exc: dict):
    """No arquivo com a excecao do subprocess: no maximo uma chamada registrada e `comando` com
    um unico binding, igual ao registrado (a chamada leva `comando` no /TR)."""
    achados = []
    if visitor.chamadas_ok > 1:
        achados.append((1, "mais de uma chamada a 'subprocess' igual a registrada"))
    funcoes = [n for n in arvore.body if isinstance(n, ast.FunctionDef) and n.name == exc["funcao"]]
    if not funcoes:
        return achados  # sem agendar nao ha chamada registrada; qualquer uso de subprocess ja reprovou
    if len(funcoes) != 1:
        return achados + [(1, f"funcao '{exc['funcao']}' duplicada")]
    corpo = list(ast.walk(funcoes[0]))
    atribuicoes = [
        n for n in corpo
        if isinstance(n, ast.Assign) and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "comando"
    ]
    if len(atribuicoes) != 1 or _dump(atribuicoes[0]) != exc["atribuicao_comando"]:
        achados.append((funcoes[0].lineno, "atribuicao de 'comando' diferente da registrada"))
    if len(atribuicoes) != 1 or _vinculos(funcoes[0], "comando") != [atribuicoes[0].targets[0]]:
        achados.append((funcoes[0].lineno, "vinculo de 'comando' fora da atribuicao registrada"))
    if _vinculos(arvore, "__file__"):
        achados.append((1, "vinculo de '__file__' no modulo"))
    topo_imports = {
        id(a) for n in arvore.body
        if (isinstance(n, ast.Import) and all(a.name in ("sys", "subprocess") for a in n.names))
        or (isinstance(n, ast.ImportFrom) and not n.level and n.module == "pathlib")
        for a in n.names if not a.asname
    }
    for nome in ("sys", "Path", "subprocess"):
        for v in _vinculos(arvore, nome):
            if id(v) not in topo_imports:
                achados.append((getattr(v, "lineno", 1), f"vinculo de '{nome}' alem do import do topo"))
    return achados


_DUNDER_ATTR_OK = {"__name__", "__module__", "__class__"}
_DUNDER_NAME_OK = {"__file__", "__name__"}
_ATTR_RISCO = {"os", "sys", "subprocess", "http", "ssl", "socket", "urllib", "asyncio", "ctypes",
               "importlib", "builtins", "modules"}
_BUILTINS = set(dir(builtins))
_INTROSPECCAO = re.compile(r"(gi|cr|ag|f|tb|co)_")  # R10: frame/codigo/traceback de gerador, corrotina e funcao


def _dunder(s: str) -> bool:
    return len(s) > 4 and s.startswith("__") and s.endswith("__")


def _nome_pontuado(no):
    partes = []
    while isinstance(no, ast.Attribute):
        partes.append(no.attr)
        no = no.value
    if isinstance(no, ast.Name):
        partes.append(no.id)
        return ".".join(reversed(partes))
    return None


def _strings(arvore) -> set:
    """Toda string de campo do arquivo (com o topo de nome pontuado): superconjunto do que _vinculos acha."""
    s = set()
    for n in ast.walk(arvore):
        for v in vars(n).values():
            s.update(x.split(".")[0] for x in (v if isinstance(v, list) else [v]) if isinstance(x, str))
    return s


def _getattr_constante(n) -> bool:
    """getattr(X, 'c'), hasattr(X, 'c') ou getattr(X, 'c', d): nome str constante, sem * e sem keyword."""
    return (isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("getattr", "hasattr")
            and not n.keywords and len(n.args) in (2, 3) and not any(isinstance(x, ast.Starred) for x in n.args)
            and isinstance(n.args[1], ast.Constant) and isinstance(n.args[1].value, str))


class _GetattrComoAtributo(ast.NodeTransformer):
    """R11: getattr/hasattr(X, 'c') vira X.c, e getattr(X, 'c', d) vira (X.c or d), para as regras de nome."""

    def visit_Call(self, node):
        self.generic_visit(node)
        if not _getattr_constante(node):
            return node
        novo = ast.copy_location(ast.Attribute(value=node.args[0], attr=node.args[1].value, ctx=ast.Load()), node)
        if len(node.args) == 3:
            novo = ast.copy_location(ast.BoolOp(op=ast.Or(), values=[novo, node.args[2]]), node)
        return novo


def _getattr_como_atributo(arvore):
    """Copia da arvore com a R11 aplicada; a original fica intacta para o R1 e o R7."""
    return ast.fix_missing_locations(_GetattrComoAtributo().visit(copy.deepcopy(arvore)))


def _nomes_externos(arvore, internos) -> tuple:
    """R9: (no, nome real) de todo `from X import n` externo e de toda cadeia de atributo mais externa com raiz
    ligada por import externo (a raiz vira o nome real: `import sys as _sys` faz `_sys.x` virar `sys.x`); as
    raizes (nome no codigo -> nomes reais); e R12: (no, nome real) de toda raiz de `from` externo lida fora de
    M.atributo e de f(...)."""
    raizes: dict[str, set] = {}
    de_from: dict[str, set] = {}
    usos, como_valor = [], []
    for n in ast.walk(arvore):
        if isinstance(n, ast.Import):
            for a in n.names:
                topo = a.name.split(".")[0]
                if topo not in internos:
                    raizes.setdefault(a.asname or topo, set()).add(a.name if a.asname else topo)
        elif isinstance(n, ast.ImportFrom) and not n.level and (n.module or "").split(".")[0] not in internos:
            for a in n.names:
                usos.append((n, f"{n.module}.{a.name}"))
                raizes.setdefault(a.asname or a.name, set()).add(f"{n.module}.{a.name}")
                de_from.setdefault(a.asname or a.name, set()).add(f"{n.module}.{a.name}")
    pai = {id(c): p for p in ast.walk(arvore) for c in ast.iter_child_nodes(p)}
    for n in ast.walk(arvore):
        p = pai.get(id(n))
        if isinstance(n, ast.Attribute) and not (isinstance(p, ast.Attribute) and p.value is n):
            raiz, _, resto = (_nome_pontuado(n) or "").partition(".")
            usos += [(n, f"{real}.{resto}") for real in sorted(raizes.get(raiz, ()))]
        elif (isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in de_from
              and not (isinstance(p, ast.Attribute) and p.value is n) and not (isinstance(p, ast.Call) and p.func is n)):
            como_valor += [(n, real) for real in sorted(de_from[n.id])]
    return usos, raizes, como_valor


def _builtins_usadas(arvore) -> dict:
    """Builtins lidas no arquivo: nome -> primeira linha."""
    usadas: dict = {}
    for n in ast.walk(arvore):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in _BUILTINS and not _dunder(n.id):
            usadas.setdefault(n.id, n.lineno)
    return usadas


def _nomes_importados(arvore) -> set:
    s = set()
    for n in ast.walk(arvore):
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                s.add(a.asname or (a.name if isinstance(n, ast.ImportFrom) else a.name.split(".")[0]))
    return s


def _modulo_de_from(rel: str, no):
    """Nome pontuado do modulo de um ImportFrom (resolve o relativo pelo caminho do arquivo)."""
    if not no.level:
        return no.module or ""
    pkg = rel.split("/")[:-1]
    if no.level - 1 > len(pkg):
        return None
    pkg = pkg[:len(pkg) - (no.level - 1)]
    return ".".join(pkg + ([no.module] if no.module else []))


def _arquivo_do_modulo(pasta: Path, mod: str):
    """Caminho relativo do .py de um modulo interno; "" para pacote sem __init__; None se nao e interno."""
    base = pasta / mod.replace(".", "/")
    if base.with_suffix(".py").is_file():
        return base.with_suffix(".py").relative_to(pasta).as_posix()
    if (base / "__init__.py").is_file():
        return (base / "__init__.py").relative_to(pasta).as_posix()
    return "" if base.is_dir() else None


def _regras_programa(arvore, rel: str, pasta: Path, importados: dict, prog: dict, exc: dict | None):
    """Listas fechadas do modo programa (R1 a R13 do Gate 2 PR-A): funcao registrada inteira, dunder,
    atributo privado, atributo de modulo de risco, modulo so como M.atributo, import de outro arquivo,
    getattr/hasattr com nome constante, builtins e nomes externos medidos no motor, atributo de introspeccao,
    getattr constante como atributo, raiz de `from` externo so em posicao fechada e texto que terceiro avalia
    (anotacao, TypeVar, type de 3 argumentos, string dunder). O R1 e o R7 olham a arvore
    original; as demais, a copia com a R11 aplicada (getattr(X, 'c') vira X.c)."""
    achados = []
    proprias = exc or {}  # listas do proprio arquivo (engine/guarda.py) somam as do programa so nele
    builtins_ok = set(prog.get("builtins", [])) | set(proprias.get("builtins", []))

    def add(n, m):
        achados.append((getattr(n, "lineno", 1), m))

    livres = set(exc.get("atributos", [])) if exc else set()  # R3/R10: lista fechada por caminho (engine/guarda.py)
    isentos: set[int] = set()
    if exc and "funcao_registrada" in exc:  # R1
        fs = [f for f in arvore.body if isinstance(f, ast.FunctionDef) and f.name == exc["funcao"]]
        if len(fs) == 1 and _dump(fs[0]) == exc["funcao_registrada"]:
            isentos = {id(n) for n in ast.walk(fs[0])}  # R7: a forma registrada fixa o getattr(nota, n)
        elif fs:  # ausente nao reprova: sem a funcao nao ha o que registrar nem isencao concedida
            achados.append((fs[0].lineno if fs else 1, f"funcao '{exc['funcao']}' diferente da forma registrada"))
    for n in ast.walk(arvore):  # R7, na original: so a forma que a R11 reescreve, com nome sem '_'
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("getattr", "hasattr")
                and id(n) not in isentos and not (_getattr_constante(n) and not n.args[1].value.startswith("_"))):
            add(n, f"'{n.func.id}' exige nome constante sem '_'")

    arvore = _getattr_como_atributo(arvore)  # R11
    pai = {id(c): n for n in ast.walk(arvore) for c in ast.iter_child_nodes(n)}
    caminhos: dict[str, str] = {}  # nome pontuado no codigo -> modulo real
    for n in ast.walk(arvore):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.asname:
                    caminhos[a.asname] = a.name
                else:
                    partes = a.name.split(".")
                    for i in range(1, len(partes) + 1):
                        caminhos[".".join(partes[:i])] = ".".join(partes[:i])
        elif isinstance(n, ast.ImportFrom):
            mod = _modulo_de_from(rel, n)
            if mod is None:
                continue
            arq = _arquivo_do_modulo(pasta, mod)
            for a in n.names:
                if a.name == "*":
                    continue
                sub_mod = f"{mod}.{a.name}" if mod else a.name
                if _arquivo_do_modulo(pasta, sub_mod) is not None:
                    caminhos[a.asname or a.name] = sub_mod
                if arq and a.name in importados.get(arq, ()):  # R6
                    add(n, f"'from {mod} import {a.name}' alcanca o import de outro arquivo")

    for n in ast.walk(arvore):
        if isinstance(n, ast.Match):  # o padrao de classe le atributo sem no Attribute; o motor nao usa match
            add(n, "match proibido no modo programa")
        if isinstance(n, ast.Name):
            if _dunder(n.id) and n.id not in _DUNDER_NAME_OK:  # R2
                add(n, f"nome '{n.id}' proibido no modo programa")
        elif isinstance(n, ast.Attribute):
            if _dunder(n.attr):  # R2
                if n.attr not in _DUNDER_ATTR_OK:
                    add(n, f"atributo '{n.attr}' proibido no modo programa")
            elif n.attr.startswith("_") and n.attr not in livres:  # R3
                add(n, f"atributo privado '{n.attr}' proibido no modo programa")
            if n.attr in _ATTR_RISCO:  # R4
                add(n, f"atributo '{n.attr}' (nome de modulo de risco) proibido no modo programa")
            if _INTROSPECCAO.match(n.attr) and n.attr not in livres:  # R10
                add(n, f"atributo de introspeccao '{n.attr}' proibido no modo programa")
            d = _nome_pontuado(n.value)
            if d in caminhos:  # R6
                arq = _arquivo_do_modulo(pasta, caminhos[d])
                if arq and n.attr in importados.get(arq, ()):
                    add(n, f"'{d}.{n.attr}' alcanca o import de outro arquivo")
        if isinstance(n, (ast.Name, ast.Attribute)) and isinstance(n.ctx, ast.Load):  # R5
            d = _nome_pontuado(n)
            p = pai.get(id(n))
            if d in caminhos and not (isinstance(p, ast.Attribute) and p.value is n):
                add(n, f"modulo '{d}' usado como valor (so M.atributo)")
        if (isinstance(n, ast.Name) and n.id in ("getattr", "hasattr") and isinstance(n.ctx, ast.Load)
                and not (isinstance(pai.get(id(n)), ast.Call) and pai[id(n)].func is n)):  # R7
            add(n, f"'{n.id}' so como chamada direta")
    for nome in sorted(_strings(arvore) & _BUILTINS):  # R8: ligar nome de builtin esconde o uso dela
        for v in _vinculos(arvore, nome):
            add(v, f"nome de builtin '{nome}' religado")
    for nome, linha in _builtins_usadas(arvore).items():  # R8
        if nome not in builtins_ok:
            achados.append((linha, f"builtin '{nome}' fora da lista do programa"))
    usos, raizes, como_valor = _nomes_externos(arvore, prog["internos"])
    nomes_ok = set(prog.get("nomes_externos", [])) | set(proprias.get("nomes_externos", []))
    for n, nome in usos:  # R9
        if nome not in nomes_ok:
            add(n, f"nome externo '{nome}' fora da lista do programa")
    valor_ok = set(prog.get("externos_como_valor", [])) | set(proprias.get("externos_como_valor", []))
    for n, real in como_valor:  # R12
        if real not in valor_ok:
            add(n, f"raiz externa '{n.id}' usada como valor ('{real}' fora de externos_como_valor)")
    for nome in sorted(raizes):  # R9: a raiz so vale pelo import que a liga
        for v in _vinculos(arvore, nome):
            if not isinstance(v, ast.alias):
                add(v, f"raiz externa '{nome}' religada")
    for n in ast.walk(arvore):  # R13 (passe 4): texto que terceiro avalia como codigo (anotacao no Pydantic etc.)
        if isinstance(n, (ast.arg, ast.AnnAssign)):
            anot = n.annotation
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            anot = n.returns
        else:
            anot = None
        if anot is not None and any(isinstance(c, ast.Constant) and isinstance(c.value, str) for c in ast.walk(anot)):
            add(anot, "texto em anotacao proibido no modo programa")
        if (isinstance(n, ast.Constant) and isinstance(n.value, str) and re.fullmatch(r"__\w+__", n.value)
                and n.value != "__main__"):
            add(n, f"texto dunder '{n.value}' proibido no modo programa")
        if isinstance(n, ast.Call):
            so_um = len(n.args) == 1 and not n.keywords and not isinstance(n.args[0], ast.Starred)
            if isinstance(n.func, ast.Name) and n.func.id == "type" and not so_um:  # o R8 impede religar 'type'
                add(n, "'type' so com 1 argumento")
            raiz, _, resto = (_nome_pontuado(n.func) or "").partition(".")
            if "typing.TypeVar" in {f"{r}.{resto}" if resto else r for r in raizes.get(raiz, ())} and not (
                    so_um and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str)):
                add(n, "'typing.TypeVar' so com 1 argumento posicional str")
    return achados


# O par (from engine import guarda; if __name__ == "__main__": guarda.instalar(...)) que o bloco registrado precisa
# ter depois do sys.path.insert; o 3o item do bloco e o sys.path.insert, que varia pouco e sai do proprio arquivo.
_BLOCO_GUARDA_PAR = [_dump(n) for n in ast.parse(
    'from engine import guarda\nif __name__ == "__main__":\n    guarda.instalar(Path(__file__).resolve())\n').body]


def _so_import_de(s, antes_ok: set) -> bool:
    doc = isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and isinstance(s.value.value, str)
    if isinstance(s, ast.Import):
        mods = [a.name for a in s.names]
    elif isinstance(s, ast.ImportFrom) and not s.level:
        mods = [s.module or ""]
    else:
        mods = []
    return doc or (bool(mods) and all(m.split(".")[0] in antes_ok for m in mods))


def _checar_bloco_guarda(arvore, bloco: list, antes_ok: set, ini_arvore) -> list:
    """O guarda em tempo de execucao instalado antes de todo import de terceiro: os comandos registrados
    (sys.path.insert, from engine import guarda e o if) em sequencia, uma vez, so com docstring e import de
    `antes_ok` antes deles. O bloco tambem precisa ser o par de instalacao conhecido (nao qualquer 3 comandos),
    e o engine/__init__.py, que roda no `from engine import guarda`, so pode importar stdlib."""
    if bloco[1:] != _BLOCO_GUARDA_PAR:
        return [(1, "bloco registrado nao e o par de instalacao do guarda (regenere com --imprimir-registro)")]
    corpo = [_dump(s) for s in arvore.body]
    inicios = [i for i in range(len(corpo)) if corpo[i:i + len(bloco)] == bloco]
    if len(inicios) != 1:
        return [(1, "bloco de instalacao do guarda ausente, alterado ou repetido")]
    for s in arvore.body[:inicios[0]]:
        if not _so_import_de(s, antes_ok):
            return [(s.lineno, "comando antes do bloco de instalacao do guarda (so docstring e import de stdlib)")]
    if ini_arvore is not None:
        for s in ini_arvore.body:
            if not _so_import_de(s, antes_ok):
                return [(getattr(s, "lineno", 1),
                         "engine/__init__.py roda antes do guarda: so docstring e import de stdlib")]
    return []


def _arquivos_programa(pasta: Path) -> list:
    """capturador.py e engine/**/*.py de <pasta>: o escopo do modo programa (S8)."""
    cap = [pasta / "capturador.py"] if (pasta / "capturador.py").is_file() else []
    return cap + (sorted((pasta / "engine").rglob("*.py")) if (pasta / "engine").is_dir() else [])


def proprios(prog: dict) -> list:
    """Arquivos (relativos a <pasta>) com listas proprias em excecoes_caminho: ficam fora das listas do programa."""
    return sorted(a for a, exc in prog.get("excecoes_caminho", {}).items() if "nomes_externos" in exc)


def medir_listas(pasta: Path, internos, sem=(), so=None) -> dict:
    """As builtins (R8), os nomes externos (R9) e os externos como valor (R12) que o motor usa, medidos na arvore
    com a R11 aplicada (a mesma que o cheque olha); fonte unica das tres listas do programa no JSON. `sem`: arquivos
    com lista propria, fora da medicao; `so`: mede um arquivo so (a lista propria dele)."""
    b, e, v = set(), set(), set()
    for caminho in _arquivos_programa(pasta):
        rel = caminho.relative_to(pasta).as_posix()
        if rel in sem or (so is not None and rel != so):
            continue
        arvore = _getattr_como_atributo(ast.parse(caminho.read_text(encoding="utf-8")))
        usos, _, como_valor = _nomes_externos(arvore, internos)
        b |= set(_builtins_usadas(arvore))
        e |= {nome for _, nome in usos}
        v |= {real for _, real in como_valor}
    return {"builtins": sorted(b), "nomes_externos": sorted(e), "externos_como_valor": sorted(v)}


def checar_programa(pasta: Path, nome: str, config: dict):
    """Modo --ferramenta: so capturador.py e engine/**/*.py de <pasta> (S8). Devolve
    lista de (caminho relativo, linha, motivo); lista vazia = verde.

    shortcut: confina o que o codigo nomeia; nao confina o valor que um chamador passa (ex.: pasta), nem o que o programa grava em disco e executa depois; atributo de objeto que nao e raiz importada passa so pelas regras de forma (dunder, privado, risco, introspeccao); texto avaliado por biblioteca de terceiro (ex.: anotacao lida pelo Pydantic) e limite da analise estatica; o guarda em tempo de execucao e pre-condicao do pode abrir; isso fica com a revisao do PR
    """
    prog = config.get("programas", {}).get(nome)
    if prog is None:
        raise KeyError(nome)
    allowlist = set(prog["stdlib"]) | set(prog["terceiros"]) | set(prog["internos"])
    excecoes = prog.get("excecoes_caminho", {})
    if not (pasta / "capturador.py").is_file():
        return [("capturador.py", 1, "arquivo ausente")]
    arquivos = _arquivos_programa(pasta)
    if len(arquivos) < 2:
        return [("engine", 1, "nenhum .py")]
    achados = []
    arvores = {}
    for caminho in arquivos:
        try:
            arvores[caminho.relative_to(pasta).as_posix()] = ast.parse(caminho.read_text(encoding="utf-8"))
        except SyntaxError:
            pass  # checar_arquivo reporta o erro de parse
    importados = {rel: _nomes_importados(a) for rel, a in arvores.items()}
    for caminho in arquivos:
        rel = caminho.relative_to(pasta).as_posix()
        for linha, motivo in checar_arquivo(caminho, allowlist, config, excecoes.get(rel), programa=True):
            achados.append((rel, linha, motivo))
        if rel in arvores:
            for linha, motivo in _regras_programa(arvores[rel], rel, pasta, importados, prog, excecoes.get(rel)):
                achados.append((rel, linha, motivo))
    cap = excecoes.get("capturador.py", {})
    if cap and "capturador.py" in arvores:  # o capturador roda como programa: o guarda e obrigatorio (fail-closed)
        if "bloco_guarda" not in cap:
            achados.append(("capturador.py", 1, "excecao de capturador.py sem bloco_guarda: o guarda nao e exigido"))
        else:
            antes_ok = set(prog["stdlib"]) | set(cap.get("imports_topo", []))
            ini = pasta / "engine" / "__init__.py"
            ini_arvore = arvores.get("engine/__init__.py") if ini.is_file() else None
            for linha, motivo in _checar_bloco_guarda(arvores["capturador.py"], cap["bloco_guarda"], antes_ok,
                                                       ini_arvore):
                achados.append(("capturador.py", linha, motivo))
    return achados


def _encontrar_arquivos(pasta: Path):
    """Retorna lista de (arquivo.py, nome_do_plugin_ou_None)."""
    dirs_skills = sorted(pasta.glob("**/skills/*/scripts"))
    if dirs_skills:
        return [
            (py, d.parent.name)
            for d in dirs_skills
            for py in sorted(d.rglob("*.py"))
        ]
    # modo motor: <pasta> ja e uma pasta scripts/ de um motor do monorepo (sem
    # skills/<nome>/scripts dentro), entao nao da pra inferir o plugin pelo
    # caminho; usa a uniao de todas as allowlists (None = sem plugin unico).
    # So serve para rodar direto nos motores do monorepo; no layout real do
    # repo publico (plugins/<nome>/skills/<nome>/scripts) vale a lista do
    # proprio plugin, isolada (ramo acima).
    return [(py, None) for py in sorted(pasta.rglob("*.py"))]


def imprimir_registro(capturador: Path) -> int:
    """Imprime (JSON) o ast.dump da chamada ao subprocess e da atribuicao de `comando` dentro de
    `agendar`, para colar em imports-permitidos.json (programas.<nome>.excecoes_caminho["capturador.py"])
    quando o `agendar` mudar de proposito. Falha se nao houver exatamente uma de cada."""
    arvore = ast.parse(capturador.read_text(encoding="utf-8"))
    ag = [n for n in arvore.body if isinstance(n, ast.FunctionDef) and n.name == "agendar"]
    if len(ag) != 1:
        print("agendar ausente ou duplicada", file=sys.stderr)
        return 1
    chamadas = [
        n for n in ast.walk(ag[0])
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and isinstance(n.func.value, ast.Name) and n.func.value.id == "subprocess"
    ]
    atrib = [
        n for n in ast.walk(ag[0])
        if isinstance(n, ast.Assign) and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "comando"
    ]
    if len(chamadas) != 1 or len(atrib) != 1:
        print("esperava exatamente uma chamada a subprocess e uma atribuicao de comando em agendar", file=sys.stderr)
        return 1
    base = [n for n in ast.parse((capturador.parent / "engine" / "base.py").read_text(encoding="utf-8")).body
            if isinstance(n, ast.FunctionDef) and n.name == "gravar_nota"]
    if len(base) != 1:
        print("gravar_nota ausente ou duplicada em engine/base.py", file=sys.stderr)
        return 1
    ins = [i for i, n in enumerate(arvore.body) if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
           and _nome_pontuado(n.value.func) == "sys.path.insert"]
    if len(ins) != 1:
        print("esperava exatamente um sys.path.insert no topo", file=sys.stderr)
        return 1
    bloco = [_dump(n) for n in arvore.body[ins[0]:ins[0] + 3]]
    if bloco[1:] != _BLOCO_GUARDA_PAR:  # nao registra lixo de um capturador.py sem o par de instalacao do guarda
        print("os dois comandos apos sys.path.insert nao sao o par de instalacao do guarda", file=sys.stderr)
        return 1
    print(json.dumps({
        "bloco_guarda": bloco,
        "funcao_registrada": _dump(ag[0]),
        "funcao_registrada_base": _dump(base[0]),
        "chamada_subprocess": _dump(chamadas[0]),
        "atribuicao_comando": _dump(atrib[0]),
    }, indent=2, ensure_ascii=False))
    return 0


def main(argv) -> int:
    if len(argv) == 3 and argv[1] == "--imprimir-registro":
        return imprimir_registro(Path(argv[2]))
    if len(argv) == 3 and argv[1] == "--imprimir-listas":  # hoje so ha um programa: capturador-de-notas
        prog = carregar_config()["programas"]["capturador-de-notas"]
        pasta, sem = Path(argv[2]), proprios(prog)
        saida = medir_listas(pasta, prog["internos"], sem=sem)
        saida["por_arquivo"] = {p: medir_listas(pasta, prog["internos"], so=p) for p in sem}
        print(json.dumps(saida, indent=2, ensure_ascii=False))
        return 0
    if len(argv) not in (2, 4) or (len(argv) == 4 and argv[2] != "--ferramenta"):
        print("uso: checar_sem_rede.py <pasta> [--ferramenta <programa>]", file=sys.stderr)
        return 2
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # consoles cp1252 do Windows nao tem U+2713
    pasta = Path(argv[1])
    config = carregar_config()
    if len(argv) == 4:
        if argv[3] not in config.get("programas", {}):
            print(f"ferramenta desconhecida: {argv[3]}", file=sys.stderr)
            return 2
        achados = checar_programa(pasta, argv[3], config)
        for rel, linha, motivo in achados:
            print(f"{rel}:{linha}: {motivo}")
        if achados:
            return 1
        print("✓ sem rede: capturador.py e engine/ (modo programa)")
        return 0
    arquivos = _encontrar_arquivos(pasta)

    total_achados = 0
    for caminho, nome_plugin in arquivos:
        allowlist = _allowlist_para_plugin(config, nome_plugin)
        for linha, motivo in checar_arquivo(caminho, allowlist, config):
            print(f"{caminho}:{linha}: {motivo}")
            total_achados += 1

    if total_achados:
        return 1
    print(f"✓ sem rede: {len(arquivos)} arquivos")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
