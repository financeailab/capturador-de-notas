from __future__ import annotations

import xml.etree.ElementTree as ET
from decimal import Decimal

from engine.model import Campo, Confianca, Fonte


def _local(tag: str) -> str:
    """Nome local da tag, sem namespace ('{ns}CNPJ' -> 'CNPJ')."""
    return tag.rsplit("}", 1)[-1]


def _find_text(root: ET.Element, nome_local: str) -> str | None:
    """Primeiro texto não-vazio cujo local-name == nome_local (busca em profundidade).

    PREMISSA: assume que o local-name é único o suficiente no documento. Vale para os
    leiautes minimais atuais; quando IBS/CBS entrar (PLAN-02+), tags como `vBC` aparecem
    em mais de um grupo — migrar para busca path-aware nesses casos.
    """
    for el in root.iter():
        if _local(el.tag) == nome_local and el.text and el.text.strip():
            return el.text.strip()
    return None


def find_text_em_grupo(
    root: ET.Element, grupos: tuple[str, ...], alvos: tuple[str, ...]
) -> str | None:
    """1o texto de um alvo (local-name em `alvos`) DENTRO do 1o elemento cujo local-name esta em
    `grupos`. Resolve a ambiguidade prestador/tomador (mesmo local-name, grupos diferentes).

    Fallback: se nenhum grupo conter o alvo, mas o proprio alvo tem nome inequivoco de tomador
    (ex.: `CidadeTomador` no leiaute SP, que fica fora de um grupo aninhado), aceita-o como leaf
    global. So vale p/ alvos cujo local-name ja nomeia o tomador (nunca p/ `Cnpj`/`cMun` genericos)."""
    for el in root.iter():
        if _local(el.tag) in grupos:
            for filho in el.iter():
                if _local(filho.tag) in alvos and filho.text and filho.text.strip():
                    return filho.text.strip()
    # leaf inequivoco (nome ja carrega "Tomador") fora de grupo aninhado
    for el in root.iter():
        nome = _local(el.tag)
        if nome in alvos and "tomador" in nome.lower() and el.text and el.text.strip():
            return el.text.strip()
    return None


def campo_xml(valor: object) -> Campo:
    """Campo extraído de XML determinístico (confiança máxima)."""
    return Campo(valor=valor, confianca=Confianca(score=1.0, fonte=Fonte.XML))


def dec(s: str | None) -> Decimal | None:
    """Decimal tolerante: valor ausente ou malformado vira None (degradacao graciosa)."""
    if s is None:
        return None
    try:
        return Decimal(s)
    except (ArithmeticError, ValueError):
        return None
