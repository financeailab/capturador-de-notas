# -*- coding: utf-8 -*-
"""Parse seguro de XML nao-confiavel — fonte unica do motor (PRD-SAN-07 S-01).

XML de nota fiscal e entrada NAO-confiavel rodando na maquina do operador.
`xml.etree.ElementTree.fromstring` cru e vulneravel a XXE (entidade externa
le arquivo local, ex.: file:///etc/passwd) e a Billion Laughs (expansao
recursiva de entidades trava a maquina). `defusedxml` desabilita DTD,
entidades e referencias externas; aqui ainda forcamos `forbid_dtd=True`
(NF-e/NFS-e do padrao BR nao usam DTD).

Todo parser do engine DEVE usar `parse()` daqui — nunca `ET.fromstring` direto.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import fromstring


def parse(xml_str: str) -> ET.Element:
    """Parseia XML rejeitando DTD/entidades (XXE, Billion Laughs).

    `EntitiesForbidden`/`DTDForbidden` herdam de ValueError (NAO de ParseError);
    traduzimos para `ET.ParseError` para cair no MESMO caminho de rejeicao que o
    motor ja trata ("XML invalido/rejeitado"), sem stack trace cru ao operador.
    """
    try:
        return fromstring(xml_str, forbid_dtd=True)
    except DefusedXmlException as e:
        raise ET.ParseError(
            f"XML rejeitado por seguranca ({e.__class__.__name__}: "
            "DTD/entidade proibida em nota fiscal)"
        ) from None
