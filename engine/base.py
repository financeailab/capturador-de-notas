"""Base local: SQLite (notas, eventos, pendencias, cursor), papel da empresa e o CSV.

Uma linha por (empresa, nota): a mesma nota chega por duas empresas configuradas com papeis
diferentes. Campo ausente fica NULL, nunca zero. Decimal guardado como texto.
"""
from __future__ import annotations

import csv
import os
import re
import sqlite3
import typing
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from engine.model import Campo, NFSeServico
from engine.parsers._helpers import _local

# Anexo de eventos (XSD tiposEventos v1.01): cancelamento, por substituicao, deferido, por oficio.
CODIGOS_CANCELA = ("101101", "105102", "105104", "305101")
PAPEIS = ("emitida", "recebida", "intermediario", "outro")


def _campo_de(anotacao):
    for a in (anotacao, *typing.get_args(anotacao)):
        if isinstance(a, type) and issubclass(a, Campo):
            return a
    return None


CAMPOS = tuple(n for n, f in NFSeServico.model_fields.items() if _campo_de(f.annotation))
DECIMAIS = frozenset(
    n for n in CAMPOS
    if Decimal in typing.get_args(
        _campo_de(NFSeServico.model_fields[n].annotation).model_fields["valor"].annotation))
FIXAS = ("cnpj_empresa", "chave", "papel", "situacao", "nsu", "arquivo")

_ESQUEMA = """
CREATE TABLE IF NOT EXISTS notas (cnpj_empresa TEXT NOT NULL, chave TEXT NOT NULL,
  papel TEXT NOT NULL, situacao TEXT NOT NULL DEFAULT 'normal', nsu INTEGER NOT NULL,
  arquivo TEXT NOT NULL, PRIMARY KEY (cnpj_empresa, chave));
CREATE TABLE IF NOT EXISTS eventos (cnpj_empresa TEXT NOT NULL, nsu INTEGER NOT NULL,
  chave TEXT NOT NULL, codigo TEXT NOT NULL, arquivo TEXT NOT NULL,
  PRIMARY KEY (cnpj_empresa, nsu));
CREATE TABLE IF NOT EXISTS pendencias (cnpj_empresa TEXT NOT NULL, nsu INTEGER NOT NULL,
  etapa TEXT NOT NULL, arquivo TEXT NOT NULL, desde TEXT NOT NULL,
  PRIMARY KEY (cnpj_empresa, nsu));
CREATE TABLE IF NOT EXISTS cursor (cnpj_empresa TEXT PRIMARY KEY, nsu INTEGER NOT NULL,
  quando TEXT NOT NULL, resultado TEXT NOT NULL);
"""


def abrir(caminho: Path) -> sqlite3.Connection:
    con = sqlite3.connect(caminho)
    con.executescript(_ESQUEMA)
    existentes = {r[1] for r in con.execute("PRAGMA table_info(notas)")}
    for n in CAMPOS:  # campo novo no modelo vira coluna nova, sem migracao manual
        if n not in existentes:
            con.execute(f'ALTER TABLE notas ADD COLUMN "{n}" TEXT')
    con.commit()
    return con


def agora() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def papel(raiz, cnpj: str) -> str:
    """CNPJ completo contra prest/emit, toma e interm (o primeiro de cada grupo)."""
    docs = {}
    for el in raiz.iter():
        nome = _local(el.tag)
        if nome in ("prest", "emit", "toma", "interm") and nome not in docs:
            docs[nome] = next((f.text.strip() for f in el
                               if _local(f.tag) in ("CNPJ", "CPF") and f.text), "")
    if cnpj in (docs.get("prest"), docs.get("emit")):
        return "emitida"
    if cnpj == docs.get("toma"):
        return "recebida"
    if cnpj == docs.get("interm"):
        return "intermediario"
    return "outro"


def mes(raiz) -> str:
    for el in raiz.iter():
        if _local(el.tag) in ("dhEmi", "dhProc") and el.text and re.match(r"\d{4}-\d{2}", el.text.strip()):
            return el.text.strip()[:7]
    return "sem-data"


def _texto(v):
    return None if v is None else str(v)


def existe_nota(con, cnpj: str, chave: str) -> bool:
    return con.execute("SELECT 1 FROM notas WHERE cnpj_empresa=? AND chave=?",
                       (cnpj, chave)).fetchone() is not None


def gravar_nota(con, cnpj: str, chave: str, papel_: str, nsu: int, arquivo: str,
                nota: NFSeServico) -> None:
    valores = {n: _texto(getattr(getattr(nota, n), "valor", None)) for n in CAMPOS}
    cols = (*FIXAS[:3], *FIXAS[4:], *CAMPOS)
    marc = ", ".join("?" * len(cols))
    nomes = ", ".join(f'"{c}"' for c in cols)
    atualiza = ", ".join(f'"{c}"=excluded."{c}"' for c in cols[2:])
    con.execute(
        f"INSERT INTO notas ({nomes}) VALUES ({marc}) "
        f"ON CONFLICT(cnpj_empresa, chave) DO UPDATE SET {atualiza}",
        (cnpj, chave, papel_, nsu, arquivo, *(valores[n] for n in CAMPOS)))
    _aplicar_situacao(con, cnpj, chave)


def gravar_evento(con, cnpj: str, nsu: int, chave: str, codigo: str, arquivo: str) -> None:
    con.execute("INSERT OR REPLACE INTO eventos VALUES (?, ?, ?, ?, ?)",
                (cnpj, nsu, chave, codigo, arquivo))
    _aplicar_situacao(con, cnpj, chave)


def _aplicar_situacao(con, cnpj: str, chave: str) -> None:
    marc = ", ".join("?" * len(CODIGOS_CANCELA))
    con.execute(
        f"UPDATE notas SET situacao='cancelada' WHERE cnpj_empresa=? AND chave=? AND EXISTS "
        f"(SELECT 1 FROM eventos e WHERE e.cnpj_empresa=? AND e.chave=? AND e.codigo IN ({marc}))",
        (cnpj, chave, cnpj, chave, *CODIGOS_CANCELA))


def gravar_pendencia(con, cnpj: str, nsu: int, etapa: str, arquivo: str) -> bool:
    """True se a pendencia e nova."""
    cur = con.execute("INSERT OR IGNORE INTO pendencias VALUES (?, ?, ?, ?, ?)",
                      (cnpj, nsu, etapa, arquivo, agora()))
    return cur.rowcount == 1


def pendencias(con, cnpj: str) -> list:
    return con.execute("SELECT nsu, arquivo FROM pendencias WHERE cnpj_empresa=? ORDER BY nsu",
                       (cnpj,)).fetchall()


def resolver_pendencia(con, cnpj: str, nsu: int) -> None:
    con.execute("DELETE FROM pendencias WHERE cnpj_empresa=? AND nsu=?", (cnpj, nsu))


def total_pendencias(con, cnpj: str) -> int:
    return con.execute("SELECT COUNT(*) FROM pendencias WHERE cnpj_empresa=?", (cnpj,)).fetchone()[0]


def ler_cursor(con, cnpj: str) -> int:
    r = con.execute("SELECT nsu FROM cursor WHERE cnpj_empresa=?", (cnpj,)).fetchone()
    return r[0] if r else 0


def gravar_cursor(con, cnpj: str, nsu: int, resultado: str) -> None:
    con.execute("INSERT INTO cursor VALUES (?, ?, ?, ?) ON CONFLICT(cnpj_empresa) DO UPDATE SET "
                "nsu=excluded.nsu, quando=excluded.quando, resultado=excluded.resultado",
                (cnpj, nsu, agora(), resultado))


# copiado de inteligencia-boleto/motor/scripts/engine/carga.py: texto de terceiro nao vira formula no Excel
_GATILHOS_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def neutralizar_formula(v):
    if isinstance(v, str) and v[:1] in _GATILHOS_FORMULA:
        return "'" + v
    return v


def exportar_csv(con, caminho: Path) -> int:
    """UTF-8 com BOM, separador `;`, decimal com virgula. Escrita atomica."""
    cols = (*FIXAS, *CAMPOS)
    nomes = ", ".join(f'"{c}"' for c in cols)
    linhas = con.execute(f"SELECT {nomes} FROM notas ORDER BY cnpj_empresa, chave").fetchall()
    tmp = caminho.with_suffix(".csv.tmp")
    with open(tmp, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(cols)
        for linha in linhas:
            w.writerow(["" if v is None else (str(v).replace(".", ",") if c in DECIMAIS else neutralizar_formula(v))
                        for c, v in zip(cols, linha)])
    os.replace(tmp, caminho)
    return len(linhas)
