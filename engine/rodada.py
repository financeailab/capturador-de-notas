"""Rodada de uma empresa: trava da pasta, pendencias, paginas do ADN e transacao por pagina.

Nada se perde em silencio: item que falha em base64, gzip, XML, evento ou parser vira pendencia
em disco (o envelope como veio) antes do cursor andar, e cada rodada reprocessa as pendencias.
"""
from __future__ import annotations

import base64
import binascii
import gzip
import json
import os
import re
import zlib
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from engine import base
from engine.adn import TAM_LOTE
from engine.parsers._helpers import _local
from engine.parsers._safe_xml import parse as parse_xml_seguro
from engine.parsers.xml_nacional import parse_nfse_nacional

if os.name == "nt":
    import msvcrt
else:
    import fcntl

TETO_PAGINAS = 200
_CODIGO_EVENTO = re.compile(r"e(\d{6})")


class Ocupado(Exception):
    """Outra rodada segura a trava da pasta."""


@contextmanager
def trava(pasta: Path):
    """Lock do sistema operacional, mantido a rodada toda; o sistema solta quando o processo
    morre. Nunca se toma trava por idade."""
    f = open(pasta / ".trava", "a+b")
    try:
        try:
            if os.name == "nt":
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise Ocupado() from None
        yield
    finally:
        f.close()


@dataclass
class Contagem:
    notas_novas: int = 0
    notas_repetidas: int = 0
    eventos: int = 0
    outros: int = 0
    pendentes_novas: int = 0
    pendentes_resolvidas: int = 0
    pendentes_total: int = 0
    paginas: int = 0
    papeis: dict = field(default_factory=lambda: dict.fromkeys(base.PAPEIS, 0))
    parada: str = ""


def _escrever(pasta: Path, rel: Path, dados: bytes) -> str:
    """Grava em pasta/rel e devolve rel (relativo, para a pasta poder mudar de lugar)."""
    caminho = pasta / rel
    caminho.parent.mkdir(parents=True, exist_ok=True)
    tmp = caminho.with_name(caminho.name + ".tmp")
    tmp.write_bytes(dados)
    os.replace(tmp, caminho)
    return rel.as_posix()


def _decodificar(item: dict):
    """(etapa que falhou ou None, texto XML ou None, raiz ou None). Sem excecao para fora."""
    try:
        bruto = base64.b64decode(item.get("ArquivoXml") or "", validate=True)
    except (binascii.Error, ValueError, TypeError):
        return "base64", None, None
    try:
        texto = gzip.decompress(bruto).decode("utf-8")
    except (OSError, EOFError, zlib.error, UnicodeDecodeError):
        return "gzip", None, None
    try:
        raiz = parse_xml_seguro(texto)
    except Exception:  # ParseError, rejeicao de DTD/entidade ou qualquer outro: vira pendencia
        return "xml", None, None
    return None, texto, raiz


def _evento(raiz):
    """(chave de 50 digitos, codigo de 6 digitos) ou None (leiaute nao reconhecido)."""
    chave = codigo = None
    for el in raiz.iter():
        nome = _local(el.tag)
        if nome == "chNFSe" and el.text and chave is None:
            chave = el.text.strip()
        elif codigo is None and (m := _CODIGO_EVENTO.fullmatch(nome)):
            codigo = m.group(1)
    if chave and codigo and re.fullmatch(r"\d{50}", chave):
        return chave, codigo
    return None


def processar_item(con, pasta: Path, cnpj: str, item: dict, c: Contagem) -> str | None:
    """Grava o item; devolve a etapa que falhou (o chamador decide a pendencia) ou None."""
    nsu = int(item["NSU"])
    tipo = str(item.get("TipoDocumento") or "").upper()
    etapa, texto, raiz = _decodificar(item)
    if etapa:
        return etapa
    if tipo == "NFSE":
        inf = next((el for el in raiz.iter() if _local(el.tag) == "infNFSe"), None)
        chave = (inf.attrib.get("Id") or "")[3:] if inf is not None else ""
        if not re.fullmatch(r"\d{50}", chave):
            return "parser"
        try:
            nota = parse_nfse_nacional(texto)
        except Exception:  # parser copiado do Leitor: qualquer falha vira pendencia
            return "parser"
        p = base.papel(raiz, cnpj)
        arq = _escrever(pasta, Path(cnpj) / base.mes(raiz) / f"{chave}.xml", texto.encode("utf-8"))
        novo = not base.existe_nota(con, cnpj, chave)
        base.gravar_nota(con, cnpj, chave, p, nsu, arq, nota)
        c.notas_novas += novo
        c.notas_repetidas += not novo
        c.papeis[p] += 1
    elif tipo == "EVENTO":
        ev = _evento(raiz)
        if ev is None:
            return "evento"
        chave, codigo = ev
        arq = _escrever(pasta, Path(cnpj) / "eventos" / f"{chave}_{codigo}_{nsu}.xml", texto.encode("utf-8"))
        base.gravar_evento(con, cnpj, nsu, chave, codigo, arq)
        c.eventos += 1
    else:
        _escrever(pasta, Path(cnpj) / "outros" / f"{nsu}.xml", texto.encode("utf-8"))
        c.outros += 1
    return None


def _pendencia(con, pasta: Path, cnpj: str, item: dict, etapa: str, c: Contagem) -> None:
    nsu = int(item["NSU"])
    arq = _escrever(pasta, Path(cnpj) / "pendentes" / f"{nsu}.json",
                    json.dumps(item, ensure_ascii=False).encode("utf-8"))
    c.pendentes_novas += base.gravar_pendencia(con, cnpj, nsu, etapa, arq)


def reprocessar_pendencias(con, pasta: Path, cnpj: str, c: Contagem) -> None:
    for nsu, _arq in base.pendencias(con, cnpj):
        # derivado da pasta atual: a coluna `arquivo` pode guardar caminho absoluto de versao antiga
        env = pasta / cnpj / "pendentes" / f"{nsu}.json"
        try:
            item = json.loads(env.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        with con:
            if processar_item(con, pasta, cnpj, item, c) is None:
                base.resolver_pendencia(con, cnpj, nsu)
                c.pendentes_resolvidas += 1
                resolvido = True
            else:
                resolvido = False
        if resolvido:
            env.unlink(missing_ok=True)


def _nsu_valido(item) -> bool:
    # 18 digitos cabem no INTEGER do SQLite (2**63-1 tem 19); NSU maior para a pagina
    return isinstance(item, dict) and re.fullmatch(r"\d{1,18}", str(item.get("NSU", ""))) is not None


def rodar_empresa(con, pasta: Path, cnpj: str, obter, teto: int = TETO_PAGINAS) -> Contagem:
    """`obter(cnpj, nsu) -> adn.Pagina`. Para em 404, lote menor que 50, 429, outro status ou teto."""
    c = Contagem()
    reprocessar_pendencias(con, pasta, cnpj, c)
    nsu = base.ler_cursor(con, cnpj)
    for _ in range(teto):
        pag = obter(cnpj, nsu)
        if pag.status == 404:
            c.parada = "fim"
            break
        if pag.status == 429:  # S13: encerra a empresa sem esperar; a proxima rodada continua
            c.parada = "429"
            break
        if pag.status != 200:
            c.parada = f"http-{pag.status}"
            break
        if not all(_nsu_valido(i) for i in pag.itens):
            c.parada = "resposta-fora-do-formato"
            break
        itens = sorted(pag.itens, key=lambda i: int(i["NSU"]))
        if not itens:
            c.parada = "fim"
            break
        c.paginas += 1
        with con:  # transacao da pagina: arquivos, linhas e pendencias primeiro, cursor depois
            for item in itens:
                etapa = processar_item(con, pasta, cnpj, item, c)
                if etapa:
                    _pendencia(con, pasta, cnpj, item, etapa, c)
            nsu = max(nsu, int(itens[-1]["NSU"]))
            base.gravar_cursor(con, cnpj, nsu, "ok")
        if len(itens) < TAM_LOTE:
            c.parada = "fim"
            break
    else:
        c.parada = "teto"
    c.pendentes_total = base.total_pendencias(con, cnpj)
    return c


def falhou(c: Contagem) -> bool:
    return c.parada not in ("fim", "teto", "429")
