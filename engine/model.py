from __future__ import annotations

from decimal import Decimal
from enum import Enum
from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class Fonte(str, Enum):
    XML = "xml"
    PDF = "pdf"
    INFERIDO = "inferido"
    INVARIANTE = "invariante"


class Confianca(BaseModel):
    score: float = Field(ge=0.0, le=1.0)
    fonte: Fonte
    motivo: str | None = None


class TipoDocumento(str, Enum):
    NFSE = "nfse"
    NFE = "nfe"
    RPS = "rps"
    DESCONHECIDO = "desconhecido"


class Campo(BaseModel, Generic[T]):
    valor: T | None = None
    confianca: Confianca


CampoStr = Campo[str]
CampoDec = Campo[Decimal]
CampoInt = Campo[int]
CampoBool = Campo[bool]


class DocumentoBase(BaseModel):
    modelo: str
    tipo_documento: str | None = None
    is_documento_fiscal: bool = True
    cancelada: bool = False  # carimbo/marca "CANCELADA" na nota (meta bool, como simples_nacional) — capture-only
    chave_acesso: CampoStr | None = None
    numero: CampoStr | None = None
    codigo_verificacao: CampoStr | None = None
    serie: CampoStr | None = None
    data_emissao: CampoStr | None = None
    competencia: CampoStr | None = None
    municipio_ibge: CampoStr | None = None
    uf: CampoStr | None = None
    # emitente / destinatario
    emitente_cnpj: CampoStr | None = None
    emitente_nome: CampoStr | None = None
    emitente_endereco: CampoStr | None = None  # endereco completo do prestador/emitente (paridade)
    destinatario_doc: CampoStr | None = None
    destinatario_endereco: CampoStr | None = None  # endereco completo do tomador/destinatario (paridade)
    municipio_tomador: CampoStr | None = None  # IBGE do tomador (path-aware)
    # retencoes federais (permanentes: IRRF/CSLL/INSS; PIS/COFINS ate 2027)
    ret_irrf: CampoDec | None = None
    ret_csll: CampoDec | None = None
    ret_pis: CampoDec | None = None
    ret_cofins: CampoDec | None = None
    ret_inss: CampoDec | None = None
    ret_inss_base: CampoDec | None = None  # base de calculo do INSS (paridade)
    ret_inss_aliquota: CampoDec | None = None  # aliquota do INSS, percentual (paridade)
    ret_federal_total: CampoDec | None = None  # vTotTribFed (informacional; conferencia = fast-follow)
    valor_liquido: CampoDec | None = None
    chave_arquivo: str | None = None
    # transicao-ready (L-11): IBS/CBS/IS opcionais, extracao = fast-follow
    versao_leiaute: str | None = None
    ibs_valor: CampoDec | None = None
    cbs_valor: CampoDec | None = None
    is_valor: CampoDec | None = None
    cst_ibscbs: CampoStr | None = None
    cclasstrib: CampoStr | None = None


DocumentoFiscalBase = DocumentoBase  # compat: nome antigo continua valendo


class NFSeServico(DocumentoBase):
    modelo: str = "NFSe"
    tipo_documento: str | None = "nfse"
    codigo_servico: CampoStr | None = None  # LC116 / cTribNac
    discriminacao: CampoStr | None = None
    vencimento: CampoStr | None = None  # data de vencimento na discriminacao (DD/MM/AAAA -> ISO)
    simples_nacional: bool = False  # optante do Simples: ISS recolhido no DAS (nao destacado)
    iss_nao_exigivel: bool = False  # tribISSQN != 1 (imunidade/nao-incidencia/exportacao/suspensa): ISS nao destacado por direito
    valor_servicos: CampoDec | None = None
    deducoes: CampoDec | None = None
    iss_base: CampoDec | None = None
    iss_aliquota: CampoDec | None = None
    iss_valor: CampoDec | None = None
    iss_retido: CampoStr | None = None
    # retencao precisa (tpRetISSQN): nao_retido | retido_tomador | retido_intermediario
    iss_tipo_retencao: CampoStr | None = None
    iss_municipio_incidencia: CampoStr | None = None  # cLocIncid (IBGE) -- onde o ISS e devido
    # intermediario de servicos (quando houver) -- paridade
    intermediario_doc: CampoStr | None = None
    intermediario_nome: CampoStr | None = None
    # valor total recebido (informativo) != valor fiscal do servico (valor_servicos) -- paridade
    valor_recebido: CampoDec | None = None


class NFeProduto(DocumentoBase):
    modelo: str = "NFe"
    tipo_documento: str | None = "nfe"
    natureza_operacao: CampoStr | None = None  # natOp: SINAL de sentido (devolucao/retorno) — capture-only, nao inverte
    vencimento: CampoStr | None = None  # data de vencimento no bloco Fatura/Duplicata (DD/MM/AAAA -> ISO)
    total_produtos: CampoDec | None = None
    frete: CampoDec | None = None
    seguro: CampoDec | None = None
    desconto: CampoDec | None = None
    outras_despesas: CampoDec | None = None
    total_nota: CampoDec | None = None
    ipi_total: CampoDec | None = None      # ICMSTot/vIPI (compoe o vNF)
    icmsst_total: CampoDec | None = None   # ICMSTot/vST (ICMS-ST, compoe o vNF)
    # agregados de itens (<det>) como SINAL — grao continua = titulo, nao item (§22.2)
    qtd_itens: CampoInt | None = None
    cfops_distintos: CampoStr | None = None  # lista de CFOPs unicos, ", "-joined
    tem_desconto_item: CampoBool | None = None
    ncm_predominante: CampoStr | None = None
    descricao_resumida: CampoStr | None = None


class TomadorReferencia(BaseModel):
    """Identidade da empresa que recebe as notas (o tomador), informada uma vez por lote."""
    cnpj: str
    municipio_ibge: str


def _campos_decimais() -> frozenset[str]:
    """Nomes dos campos Campo[Decimal] em todas as classes do modelo (fonte unica de _DECIMAIS)."""
    nomes: set[str] = set()
    for cls in (DocumentoBase, NFSeServico, NFeProduto):
        for nome, f in cls.model_fields.items():
            if "Decimal" in str(f.annotation):   # CampoDec = Campo[Decimal] | None
                nomes.add(nome)
    return frozenset(nomes)


CAMPOS_DECIMAIS = _campos_decimais()
