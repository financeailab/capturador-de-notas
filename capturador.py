"""capturador de notas: baixa as NFS-e emitidas e recebidas do ADN para uma pasta local.

  python capturador.py configurar --pasta P [--cnpj 14 digitos] [--pfx caminho]
  python capturador.py baixar --pasta P
  python capturador.py agendar --pasta P [--hora 06:00]

A senha do certificado fica no cofre do sistema (keyring), nunca em arquivo nem em argumento.
Saida (stdout, stderr, log): so contagens e rotulos fixos, nunca texto de nota.
Codigos: 0 ok, 1 empresa falhou ou pendencia nova, 2 configuracao ou uso invalido, 3 ocupado,
4 o guarda bloqueou uma operacao (rede fora do ADN, processo fora do agendar ou texto que executa).
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from engine import guarda

if __name__ == "__main__":
    guarda.instalar(Path(__file__).resolve())

import keyring

from engine import adn, base, rodada

SERVICO = "capturador-de-notas"
TAREFA = "capturador-de-notas"
CONFIG = "capturador.json"
LOG = "capturador.log"
AVISO_DIAS = 30
_COFRE_RUIM = ("keyring.backends.fail", "keyring.backends.null", "keyrings.alt")


def _erro(msg: str) -> None:
    print(msg, file=sys.stderr)


def _cofre_ok() -> bool:
    kr = keyring.get_keyring()
    todos = kr.backends if hasattr(kr, "backends") else [kr]
    return bool(todos) and not any(type(b).__module__.startswith(_COFRE_RUIM) for b in todos)


def _dentro_de_repo(p: Path) -> bool:
    return any((d / ".git").exists() for d in (p, *p.parents))


def _mascara(cnpj: str) -> str:
    return "*" * 10 + cnpj[-4:]


def _ler_config(pasta: Path):
    """dict valido, None se nao existe, False se existe e esta invalido."""
    arq = pasta / CONFIG
    if not arq.exists():
        return None
    try:
        cfg = json.loads(arq.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    empresas = cfg.get("empresas") if isinstance(cfg, dict) else None
    ok = isinstance(empresas, list) and all(
        isinstance(e, dict) and re.fullmatch(r"\d{14}", str(e.get("cnpj", ""))) and e.get("pfx")
        for e in empresas)
    return cfg if ok else False


def _registrar(pasta: Path, linhas: list) -> None:
    for linha in linhas:
        print(linha)
    try:
        with open(pasta / LOG, "a", encoding="utf-8") as f:
            for linha in linhas:
                f.write(f"{base.agora()} {linha}\n")
    except OSError:
        _erro("aviso: nao consegui escrever o log")


def _gravar_config(pasta: Path, cfg: dict) -> None:
    """Atomica: temporario exclusivo na mesma pasta + os.replace; a anterior so some quando a nova existe."""
    fd, nome = tempfile.mkstemp(prefix=CONFIG + ".", suffix=".tmp", dir=pasta)
    tmp = Path(nome)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(cfg, indent=2))
        os.replace(tmp, pasta / CONFIG)
    finally:
        tmp.unlink(missing_ok=True)


def _restaurar_senha(cnpj: str, anterior: str | None) -> None:
    try:
        if anterior is None:
            keyring.delete_password(SERVICO, cnpj)
        else:
            keyring.set_password(SERVICO, cnpj, anterior)
    except Exception:  # o cofre ja falhou uma vez; a mensagem do chamador cobre
        _erro("aviso: nao consegui restaurar a senha anterior no cofre")


def configurar(pasta: Path, cnpj: str | None, pfx: str | None) -> int:
    if not _cofre_ok():
        _erro("o cofre de senhas do sistema nao esta disponivel; nada foi gravado")
        return 2
    pasta = pasta.expanduser().resolve()
    if _dentro_de_repo(pasta):
        _erro("a pasta fica dentro de um repositorio git; escolha uma pasta fora dele")
        return 2
    cfg = _ler_config(pasta)
    if cfg is False:
        _erro(f"{CONFIG} existe mas esta invalido; corrija ou apague antes de configurar")
        return 2
    cnpj = re.sub(r"\D", "", cnpj or input("CNPJ da empresa (14 digitos): "))
    if len(cnpj) != 14:
        _erro("o CNPJ precisa de 14 digitos")
        return 2
    caminho = Path(pfx or input("Caminho do arquivo .pfx: ").strip().strip('"')).expanduser().resolve()
    if _dentro_de_repo(caminho):
        _erro("o .pfx esta dentro de um repositorio git; guarde o certificado fora dele")
        return 2
    senha = getpass.getpass("Senha do certificado (nao aparece na tela): ")
    try:
        cert = adn.abrir_pfx(caminho.read_bytes(), senha)
    except OSError:
        _erro("nao consegui ler o arquivo .pfx")
        return 2
    except adn.ErroCertificado:
        _erro("certificado recusado: senha errada, arquivo que nao e PFX ou certificado que nao e e-CNPJ")
        return 2
    if cert.cnpj[:8] != cnpj[:8]:
        _erro("o CNPJ informado nao e da mesma raiz do certificado")
        return 2
    if cert.validade <= datetime.now(timezone.utc):
        _erro("o certificado esta vencido")
        return 2
    pasta.mkdir(parents=True, exist_ok=True)
    try:
        with rodada.trava(pasta):  # serializa com outro configurar e com o baixar (Gate 1B, passe 2)
            return _publicar(pasta, cnpj, caminho, senha, cert)
    except rodada.Ocupado:
        _erro("outra execucao esta usando esta pasta; nada foi gravado, tente de novo em instantes")
        return 3


def _publicar(pasta: Path, cnpj: str, caminho: Path, senha: str, cert) -> int:
    """Sob a trava: rele o cadastro, grava a senha e publica a configuracao (ou desfaz a senha)."""
    cfg = _ler_config(pasta)
    if cfg is False:
        _erro(f"{CONFIG} existe mas esta invalido; corrija ou apague antes de configurar")
        return 2
    cfg = cfg or {"empresas": []}
    cfg["empresas"] = [e for e in cfg["empresas"] if e["cnpj"] != cnpj] + [{"cnpj": cnpj, "pfx": str(caminho)}]
    try:
        anterior = keyring.get_password(SERVICO, cnpj)
        keyring.set_password(SERVICO, cnpj, senha)
    except Exception as e:  # cofre travado ou recusado: so o tipo sai
        _erro(f"o cofre de senhas recusou a gravacao ({type(e).__name__}); nada foi gravado")
        return 2
    try:
        _gravar_config(pasta, cfg)
    except OSError:
        _restaurar_senha(cnpj, anterior)
        _erro("nao consegui gravar a configuracao; a anterior e a senha anterior ficaram como estavam")
        return 2
    print(f"empresa {_mascara(cnpj)} configurada; certificado valido ate {cert.validade:%Y-%m-%d}; "
          f"{len(cfg['empresas'])} empresa(s) nesta pasta")
    return 0


def _empresa(con, pasta: Path, emp: dict) -> tuple[list, bool]:
    """(linhas de saida, falhou). Qualquer excecao fica nesta empresa (S14): as outras seguem."""
    try:
        return _rodar_empresa(con, pasta, emp)
    except Exception as e:  # cofre travado, PFX estranho, disco: so o tipo sai
        return [f"empresa {_mascara(emp['cnpj'])}: FALHOU ({type(e).__name__})"], True


def _rodar_empresa(con, pasta: Path, emp: dict) -> tuple[list, bool]:
    cnpj = emp["cnpj"]
    rot = f"empresa {_mascara(cnpj)}:"
    senha = keyring.get_password(SERVICO, cnpj)
    if senha is None:
        return [f"{rot} FALHOU (senha ausente no cofre; rode configurar)"], True
    try:
        cert = adn.abrir_pfx(Path(emp["pfx"]).read_bytes(), senha)
    except OSError:
        return [f"{rot} FALHOU (nao consegui ler o .pfx)"], True
    except adn.ErroCertificado:
        return [f"{rot} FALHOU (certificado recusado)"], True
    agora = datetime.now(timezone.utc)
    if cert.cnpj[:8] != cnpj[:8]:
        return [f"{rot} FALHOU (o certificado e de outra raiz de CNPJ)"], True
    if cert.validade <= agora:
        return [f"{rot} FALHOU (certificado vencido)"], True
    linhas = []
    if cert.validade - agora <= timedelta(days=AVISO_DIAS):
        linhas.append(f"{rot} aviso: o certificado vence em {(cert.validade - agora).days} dia(s)")
    try:
        ctx = adn.contexto_tls(cert)
        c = rodada.rodar_empresa(con, pasta, cnpj, partial(adn.obter_pagina, ctx))
    except adn.ErroRede:
        return [*linhas, f"{rot} FALHOU (guarda de rede: resposta fora do ADN)"], True
    except Exception as e:  # rede, TLS, disco: so o tipo sai
        return [*linhas, f"{rot} FALHOU ({type(e).__name__})"], True
    p = c.papeis
    linhas.append(
        f"{rot} notas novas {c.notas_novas}, repetidas {c.notas_repetidas} (emitidas {p['emitida']}, "
        f"recebidas {p['recebida']}, intermediario {p['intermediario']}, outro {p['outro']}); "
        f"eventos {c.eventos}; outros {c.outros}; pendentes novas {c.pendentes_novas}, "
        f"resolvidas {c.pendentes_resolvidas}, total {c.pendentes_total}; paginas {c.paginas}; "
        f"parada {c.parada}")
    return linhas, rodada.falhou(c) or c.pendentes_novas > 0


def baixar(pasta: Path) -> int:
    pasta = pasta.expanduser().resolve()
    cfg = _ler_config(pasta)
    if not cfg or not cfg["empresas"]:
        _erro("configuracao ausente ou invalida nesta pasta; rode configurar")
        return 2
    try:
        with rodada.trava(pasta):
            con = base.abrir(pasta / "base.sqlite")
            try:
                linhas, codigo = [], 0
                for emp in cfg["empresas"]:
                    if guarda.bloqueou():
                        break
                    saida, falhou = _empresa(con, pasta, emp)
                    linhas += saida
                    codigo = 1 if falhou else codigo
                linhas.append(f"notas.csv: {base.exportar_csv(con, pasta / 'notas.csv')} linha(s)")
            finally:
                con.close()
            _registrar(pasta, linhas)
            return codigo
    except rodada.Ocupado:
        _erro("outra rodada esta em andamento nesta pasta")
        return 3


def _nome_tarefa(pasta: Path) -> str:
    """Uma tarefa por pasta; minuscula porque o Windows nao diferencia maiuscula."""
    return f"{TAREFA}-{hashlib.sha256(str(pasta).lower().encode('utf-8')).hexdigest()[:8]}"


def agendar(pasta: Path, hora: str) -> int:
    pasta = pasta.expanduser().resolve()
    if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", hora):
        _erro("a hora vai no formato HH:MM")
        return 2
    if not _ler_config(pasta):
        _erro("configuracao ausente ou invalida nesta pasta; rode configurar")
        return 2
    # shortcut: o /TR do schtasks aceita ate 261 caracteres; se estourar, agendar um .cmd na pasta
    nome = _nome_tarefa(pasta)
    # a barra final da raiz (D:\) escaparia a aspa de fechamento no argv da tarefa; dobrada, chega inteira
    fim = "\\" if str(pasta).endswith("\\") else ""
    comando = f'"{sys.executable}" "{Path(__file__).resolve()}" baixar --pasta "{pasta}{fim}"'
    if os.name == "nt":
        r = subprocess.run(["schtasks", "/Create", "/F", "/SC", "DAILY", "/TN", nome, "/ST", hora,
                            "/TR", comando], capture_output=True)
        if r.returncode != 0:
            _erro(f"o agendador do Windows recusou a tarefa (codigo {r.returncode})")
            return 1
        print(f"tarefa diaria '{nome}' criada para as {hora}; ela so roda com o computador ligado, "
              "e a rodada seguinte recupera o que faltou")
        return 0
    h, m = hora.split(":")
    print("adicione esta linha ao crontab (crontab -e):")
    print(f"{int(m)} {int(h)} * * * {comando}")
    return 0


def _despachar() -> int:
    ap = argparse.ArgumentParser(prog="capturador", description="Baixa NFS-e do ADN para uma pasta local.")
    sub = ap.add_subparsers(dest="comando", required=True)
    cfg = sub.add_parser("configurar", help="cadastra uma empresa e guarda a senha no cofre")
    cfg.add_argument("--cnpj")
    cfg.add_argument("--pfx")
    sub.add_parser("baixar", help="uma rodada para cada empresa da pasta")
    ag = sub.add_parser("agendar", help="rodada diaria pelo agendador do sistema")
    ag.add_argument("--hora", default="06:00")
    for s in sub.choices.values():
        s.add_argument("--pasta", required=True, type=Path)
    a = ap.parse_args()
    if a.comando == "configurar":
        return configurar(a.pasta, a.cnpj, a.pfx)
    if a.comando == "baixar":
        return baixar(a.pasta)
    return agendar(a.pasta, a.hora)


def main() -> int:
    """Com a trava do guarda ligada o codigo e 4, mesmo que uma biblioteca tenha engolido o bloqueio."""
    try:
        codigo = _despachar()
    except BaseException:
        if guarda.bloqueou():
            return 4
        raise
    return 4 if guarda.bloqueou() else codigo


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
