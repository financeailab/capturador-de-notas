"""ADN do Sistema Nacional NFS-e: certificado A1, contexto TLS e o GET de distribuicao.

Unico modulo com rede. So HTTPS na porta 443, so os hosts do ADN, so GET, sem seguir
redirecionamento (http.client nao segue). Nenhuma mensagem leva texto vindo do servidor.
"""
from __future__ import annotations

import http.client
import json
import re
import secrets
import shutil
import ssl
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    PrivateFormat,
    pkcs12,
)

HOSTS = ("adn.nfse.gov.br", "adn.producaorestrita.nfse.gov.br")
PORTA = 443
TAM_LOTE = 50


class ErroCertificado(Exception):
    """Mensagem fixa escrita aqui, nunca texto do arquivo."""


class ErroRede(Exception):
    """Guarda de rede: host, porta ou redirecionamento fora do ADN."""


@dataclass(frozen=True)
class Certificado:
    cnpj: str
    validade: datetime
    pem_cadeia: bytes
    chave: object


@dataclass(frozen=True)
class Pagina:
    status: int
    itens: list


def abrir_pfx(dados: bytes, senha: str) -> Certificado:
    try:
        chave, cert, extras = pkcs12.load_key_and_certificates(dados, senha.encode())
    except (ValueError, TypeError):
        raise ErroCertificado("senha errada ou arquivo que nao e PFX") from None
    if chave is None or cert is None:
        raise ErroCertificado("PFX sem chave ou sem certificado")
    cn = next((a.value for a in cert.subject if a.oid.dotted_string == "2.5.4.3"), "")
    doc = re.sub(r"\D", "", cn.rsplit(":", 1)[-1]) if ":" in cn else ""
    if len(doc) != 14:
        raise ErroCertificado("o certificado nao e e-CNPJ")
    pem = b"".join(c.public_bytes(Encoding.PEM) for c in [cert, *(extras or [])])
    return Certificado(doc, cert.not_valid_after_utc, pem, chave)


def contexto_tls(cert: Certificado) -> ssl.SSLContext:
    """A chave so vai a disco cifrada, com senha de uso unico; o temporario some em finally."""
    ctx = ssl.create_default_context()
    senha = secrets.token_urlsafe(32)
    pasta = Path(tempfile.mkdtemp(prefix="capturador-"))
    try:
        cadeia, chave = pasta / "cadeia.pem", pasta / "chave.pem"
        cadeia.write_bytes(cert.pem_cadeia)
        chave.write_bytes(cert.chave.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(senha.encode())))
        ctx.load_cert_chain(cadeia, chave, password=senha)
    finally:
        shutil.rmtree(pasta, ignore_errors=True)
    return ctx


def obter_pagina(ctx, cnpj: str, nsu: int, host: str = HOSTS[0], porta: int = PORTA,
                 conexao=http.client.HTTPSConnection, timeout: float = 60) -> Pagina:
    """Uma pagina de distribuicao a partir do `nsu`. 200 com lote, 404 sem documento novo,
    qualquer outro status volta como esta (quem chama decide); 3xx e erro de guarda."""
    if host not in HOSTS or porta != PORTA:
        raise ErroRede("host ou porta fora do ADN")
    if not re.fullmatch(r"\d{14}", cnpj) or not isinstance(nsu, int) or nsu < 0:
        raise ValueError("cnpj ou nsu invalido")
    con = conexao(host, porta, context=ctx, timeout=timeout)
    try:
        con.request("GET", f"/contribuintes/DFe/{nsu}?lote=true&cnpjConsulta={cnpj}",
                    headers={"Accept": "application/json"})
        r = con.getresponse()
        corpo = r.read()
        status = r.status
    finally:
        con.close()
    if 300 <= status < 400:
        raise ErroRede("redirecionamento recusado")
    if status != 200:
        return Pagina(status, [])
    try:
        lote = json.loads(corpo or b"{}").get("LoteDFe") or []
    except (ValueError, AttributeError):
        raise ErroRede("resposta fora do formato") from None
    if not isinstance(lote, list):
        raise ErroRede("resposta fora do formato")
    return Pagina(200, lote)
