from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation

_RETIDO = {"1", "true", "t", "s", "sim"}

_LIXO_DECIMAL = re.compile(r"[R$\s*]")


def normalizar_decimal_br(texto) -> Decimal | None:
    """Texto numerico BR (1.234,56) OU US/ponto-decimal (13305.60) -> Decimal.
    Remove R$, espacos e o '*' de rodape. None SO quando nao ha numero (nunca perde valor em silencio
    por causa de separador: quem chama trata o None como 'ilegivel', nao como 'ausente legitimo')."""
    if texto is None:
        return None
    s = _LIXO_DECIMAL.sub("", str(texto))
    if not s or not any(c.isdigit() for c in s):
        return None
    tem_v, tem_p = "," in s, "." in s
    if tem_v and tem_p:
        # o ULTIMO separador e o decimal: BR '1.234,56' (virgula) ou US '1,234.56' (ponto)
        if s.rfind(",") > s.rfind("."):
            s = s.replace(".", "").replace(",", ".")   # BR: ponto=milhar, virgula=decimal
        else:
            s = s.replace(",", "")                      # US: virgula=milhar
    elif tem_v:
        s = s.replace(",", ".")                          # virgula sozinha = decimal BR
    # ponto sozinho (ou nenhum) = ja US/decimal ou inteiro -> deixa
    try:
        return Decimal(s)
    except (InvalidOperation, ValueError):
        return None


def normalizar_aliquota(valor: Decimal | None) -> Decimal | None:
    """Normaliza aliquota ISS: valores em (0, 1) sao fracao (ex.: 0.05 = 5%) e viram percentual (x100).
    Valores >= 1 sao tratados como percentual e passam inalterados. O valor exato 1.00 e ambiguo
    (1% vs fracao de 100%) e passa inalterado, o que e seguro pois nenhuma prefeitura usa 100% de ISS."""
    if valor is None:
        return None
    if Decimal("0") < valor < Decimal("1"):
        return valor * Decimal("100")
    return valor


def iss_e_retido(valor: str | None) -> bool:
    """Interpreta o indicador de ISS retido (1/2, true/false, S/N) como booleano."""
    if valor is None:
        return False
    return valor.strip().lower() in _RETIDO


_RETIDO_NACIONAL = {"2", "3"}  # tpRetISSQN: 1=Nao retido, 2=Retido Tomador, 3=Retido Intermediario


def retido_nacional(tp: str | None) -> bool:
    """tpRetISSQN do leiaute NFS-e nacional: 2 (Tomador) ou 3 (Intermediario) = retido; 1/ausente = nao."""
    if tp is None:
        return False
    return tp.strip() in _RETIDO_NACIONAL


# Valores canonicos de iss_tipo_retencao.
RET_NAO = "nao_retido"
RET_TOMADOR = "retido_tomador"
RET_INTERMEDIARIO = "retido_intermediario"

# tpRetISSQN (leiaute NFS-e nacional): 1=Nao retido, 2=Retido Tomador, 3=Retido Intermediario.
_TP_ISSQN = {"1": RET_NAO, "2": RET_TOMADOR, "3": RET_INTERMEDIARIO}


def tipo_retencao_iss(tp: str | None) -> str | None:
    """Mapeia tpRetISSQN -> tipo de retencao canonico. Codigo ausente/desconhecido -> None."""
    if tp is None:
        return None
    return _TP_ISSQN.get(tp.strip())


def tipo_retencao_de_booleano(retido: bool) -> str:
    """Leiautes ABRASF/SP so distinguem retido/nao -> mapeia retido para 'retido_tomador' (caso comum em AP)."""
    return RET_TOMADOR if retido else RET_NAO


def retido_por_tipo(tipo: str | None) -> bool | None:
    """True se o ISS foi retido (tomador OU intermediario); False se nao_retido; None se desconhecido."""
    if tipo is None:
        return None
    return tipo in (RET_TOMADOR, RET_INTERMEDIARIO)
