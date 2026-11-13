from __future__ import annotations

import xml.etree.ElementTree as ET

from engine.parsers._helpers import _local

# Campo canônico -> rótulos ABRASF (local-names), em ordem de preferência.
# Cresce com o loop de aprendizado (resource editável, não lógica hardcoded).
ALIASES_ABRASF: dict[str, list[str]] = {
    "numero": ["Numero"],
    "codigo_verificacao": ["CodigoVerificacao"],
    "data_emissao": ["DataEmissao"],
    "valor_servicos": ["ValorServicos"],
    "iss_valor": ["ValorIss", "ValorISS"],
    "iss_aliquota": ["Aliquota", "AliquotaISS", "AliquotaServico"],
    "iss_base": ["BaseCalculo"],
    "valor_liquido": ["ValorLiquidoNfse", "ValorLiquido"],
    "codigo_servico": ["ItemListaServico", "CodigoTributacaoMunicipio"],
    "discriminacao": ["Discriminacao"],
    "iss_retido": ["IssRetido"],
    "emitente_cnpj": ["Cnpj"],
    "emitente_nome": ["RazaoSocial"],
    # "tomador_cnpj": ["Cnpj"],        # AMBIGUO: mesmo local-name que prestador -> requer path-aware (PLAN-03)
    # "tomador_nome": ["RazaoSocial"], # idem
}


def resolver_alias(root: ET.Element, aliases: list[str]) -> tuple[str | None, str | None]:
    """Retorna (texto, alias_usado) do 1º alias presente no doc; (None, None) se nenhum."""
    for nome in aliases:
        for el in root.iter():
            if _local(el.tag) == nome and el.text and el.text.strip():
                return el.text.strip(), nome
    return None, None


# São Paulo próprio (Nota Fiscal Paulistana) — não-ABRASF, rótulos próprios.
ALIASES_SP: dict[str, list[str]] = {
    "numero": ["NumeroNFe"],
    "codigo_verificacao": ["CodigoVerificacao"],
    "data_emissao": ["DataEmissaoNFe"],
    "valor_servicos": ["ValorServicos"],
    "iss_valor": ["ValorISS"],
    "iss_aliquota": ["AliquotaServicos"],
    "iss_base": ["BaseCalculo", "ValorServicos"],  # SP não emite base separada -> fallback servicos
    "valor_liquido": ["ValorLiquidoNFe", "ValorLiquido"],
    "codigo_servico": ["CodigoServico"],
    "discriminacao": ["Discriminacao"],
    "iss_retido": ["ISSRetido"],
    "emitente_cnpj": ["CNPJ"],  # AMBIGUO p/ tomador: mesmo local-name -> requer path-aware (PLAN futuro)
    "emitente_nome": ["RazaoSocialPrestador"],
    # "tomador_cnpj": ["CNPJ"],            # AMBIGUO: mesmo local-name que prestador -> path-aware (PLAN futuro)
    # "tomador_nome": ["RazaoSocialTomador"],  # idem
}


# Grupos e alvos do TOMADOR (path-aware) — cobre nacional/ABRASF/SP.
GRUPOS_TOMADOR = ("toma", "Tomador", "TomadorServico", "CPFCNPJTomador", "DadosTomador")
ALVOS_TOMADOR_CNPJ = ("Cnpj", "CNPJ")
ALVOS_TOMADOR_MUNICIPIO = ("cMun", "CodigoMunicipio", "CidadeTomador", "cMunFG", "CodigoMunicipioTomador")
