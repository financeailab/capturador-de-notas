from __future__ import annotations

from engine.model import NFSeServico
from engine.normalizacao import retido_nacional, tipo_retencao_iss
from engine.parsers._helpers import _find_text, _local, campo_xml, dec, find_text_em_grupo
from engine.parsers._safe_xml import parse as parse_xml_seguro
from engine.parsers.aliases import GRUPOS_TOMADOR, ALVOS_TOMADOR_CNPJ, ALVOS_TOMADOR_MUNICIPIO


def parse_nfse_nacional(xml_str: str) -> NFSeServico:
    """Parser deterministico do leiaute NFS-e nacional (namespace .../nfse)."""
    root = parse_xml_seguro(xml_str)
    inf = next((el for el in root.iter() if _local(el.tag) == "infNFSe"), root)
    chave = inf.attrib.get("Id")

    tp_ret = _find_text(root, "tpRetISSQN")
    tipo_ret = tipo_retencao_iss(tp_ret)

    _dest = find_text_em_grupo(root, GRUPOS_TOMADOR, ALVOS_TOMADOR_CNPJ)
    _mun_tom = find_text_em_grupo(root, GRUPOS_TOMADOR, ALVOS_TOMADOR_MUNICIPIO)

    _op = _find_text(root, "opSimpNac")
    _trib = _find_text(root, "tribISSQN")

    return NFSeServico(
        simples_nacional=_op in ("2", "3"),
        iss_nao_exigivel=(_trib is not None and _trib != "1"),
        destinatario_doc=campo_xml(_dest) if _dest else None,
        municipio_tomador=campo_xml(_mun_tom) if _mun_tom else None,
        chave_acesso=campo_xml(chave) if chave else None,
        numero=campo_xml(_find_text(root, "nNFSe")),
        emitente_cnpj=campo_xml(_find_text(root, "CNPJ")),
        emitente_nome=campo_xml(_find_text(root, "xNome")),
        codigo_servico=campo_xml(_find_text(root, "cTribNac")),
        discriminacao=campo_xml(_find_text(root, "xDescServ")),
        valor_servicos=campo_xml(dec(_find_text(root, "vServ"))),
        iss_base=campo_xml(dec(_find_text(root, "vBC"))),
        iss_aliquota=campo_xml(dec(_find_text(root, "pAliqAplic"))),
        iss_valor=campo_xml(dec(_find_text(root, "vISSQN"))),
        data_emissao=campo_xml(_find_text(root, "dhEmi")),
        iss_retido=campo_xml("true" if retido_nacional(tp_ret) else "false"),
        iss_tipo_retencao=campo_xml(tipo_ret) if tipo_ret else None,
        iss_municipio_incidencia=campo_xml(_find_text(root, "cLocIncid")),
        ret_federal_total=campo_xml(dec(_find_text(root, "vTotTribFed"))),
        ret_irrf=campo_xml(dec(_find_text(root, "vRetIRRF"))),
        ret_csll=campo_xml(dec(_find_text(root, "vRetCSLL"))),
        valor_liquido=campo_xml(dec(_find_text(root, "vLiq"))),
    )
