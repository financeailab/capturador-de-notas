"""Dados sinteticos: NFS-e, evento, envelope do ADN, ADN falso e PFX ficticio. Nada real."""
from __future__ import annotations

import base64
import gzip
import json
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12
from cryptography.x509.oid import NameOID

from engine.adn import Pagina, TAM_LOTE

CNPJ_A = "11222333000181"
CNPJ_B = "99888777000100"
MARCADOR = "CONTRAPARTE MARCADOR ZQX"  # nome da nota sintetica: nunca pode aparecer na saida
SENHA = "senha-canario-7Kq2"


def chave(n: int) -> str:
    return f"{35503011222333000181:020d}{n:030d}"


def nfse_xml(n: int, prest: str = CNPJ_B, toma: str = CNPJ_A, aliquota: bool = True,
             dh: str = "2026-03-15T10:00:00-03:00") -> bytes:
    aliq = "<pAliqAplic>2.00</pAliqAplic>" if aliquota else ""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<NFSe xmlns="http://www.sped.fazenda.gov.br/nfse"><infNFSe Id="NFS{chave(n)}">
<nNFSe>{n}</nNFSe><emit><CNPJ>{prest}</CNPJ><xNome>{MARCADOR}</xNome></emit>
<valores><vBC>1000.00</vBC>{aliq}<vISSQN>20.00</vISSQN><vLiq>980.00</vLiq></valores>
<DPS><infDPS><dhEmi>{dh}</dhEmi><prest><CNPJ>{prest}</CNPJ></prest>
<toma><CNPJ>{toma}</CNPJ><xNome>{MARCADOR}</xNome></toma>
<serv><cServ><cTribNac>010101</cTribNac><xDescServ>{MARCADOR}</xDescServ></cServ></serv>
<valores><vServPrest><vServ>1000.00</vServ></vServPrest></valores></infDPS></DPS>
</infNFSe></NFSe>""".encode("utf-8")


def evento_xml(n: int, codigo: str = "101101") -> bytes:
    """Estrutura do XSD oficial (evento_v1.01.xsd): chNFSe e o elemento eNNNNNN em infPedReg."""
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<evento xmlns="http://www.sped.fazenda.gov.br/nfse" versao="1.01"><infEvento Id="EVT{chave(n)}{codigo}001">
<verAplic>T</verAplic><ambGer>2</ambGer><nSeqEvento>1</nSeqEvento><dhProc>2026-03-16T10:00:00-03:00</dhProc>
<nDFSe>1</nDFSe><pedRegEvento versao="1.01"><infPedReg Id="PRE{chave(n)}{codigo}001"><tpAmb>2</tpAmb>
<verAplic>T</verAplic><dhEvento>2026-03-16T10:00:00-03:00</dhEvento><CNPJAutor>{CNPJ_B}</CNPJAutor>
<chNFSe>{chave(n)}</chNFSe><e{codigo}><xDesc>Cancelamento de NFS-e</xDesc><cMotivo>1</cMotivo>
<xMotivo>{MARCADOR}</xMotivo></e{codigo}></infPedReg></pedRegEvento></infEvento></evento>""".encode("utf-8")


def envelope(nsu: int, xml: bytes, tipo: str = "NFSE") -> dict:
    return {"NSU": nsu, "TipoDocumento": tipo,
            "ArquivoXml": base64.b64encode(gzip.compress(xml)).decode("ascii")}


def ilegivel(nsu: int) -> dict:
    return {"NSU": nsu, "TipoDocumento": "NFSE", "ArquivoXml": base64.b64encode(b"nao e gzip").decode()}


class ADNFalso:
    """`obter(cnpj, nsu)` sobre listas de envelopes por CNPJ; `roteiro` troca a resposta da chamada i."""

    def __init__(self, por_cnpj: dict, roteiro: dict | None = None):
        self.por_cnpj, self.roteiro, self.chamadas = por_cnpj, roteiro or {}, []

    def __call__(self, cnpj: str, nsu: int) -> Pagina:
        self.chamadas.append((cnpj, nsu))
        i = len(self.chamadas) - 1
        if i in self.roteiro:
            return self.roteiro[i]
        lote = [e for e in self.por_cnpj.get(cnpj, []) if e["NSU"] > nsu][:TAM_LOTE]
        return Pagina(200, lote) if lote else Pagina(404, [])


def pfx(cnpj: str = CNPJ_A, senha: str = SENHA, dias: int = 365, cn: str | None = None) -> bytes:
    chave_priv = ec.generate_private_key(ec.SECP256R1())
    nome = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn or f"EMPRESA FICTICIA LTDA:{cnpj}")])
    agora = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(nome).issuer_name(nome)
            .public_key(chave_priv.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(agora - timedelta(days=400)).not_valid_after(agora + timedelta(days=dias))
            .sign(chave_priv, hashes.SHA256()))
    return pkcs12.serialize_key_and_certificates(b"teste", chave_priv, cert, None,
                                                 BestAvailableEncryption(senha.encode()))


def json_bytes(obj) -> bytes:
    return json.dumps(obj).encode()
