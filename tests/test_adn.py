"""V5 (chave no temporario) e V6 (guarda de rede no transporte real, contra servidor TLS local)."""
from __future__ import annotations

import ast
import http.client
import http.server
import ipaddress
import re
import ssl
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from engine import adn
from tests.sinteticos import CNPJ_A, SENHA, json_bytes, pfx


# ---------- certificado A1 ----------

def test_abrir_pfx_le_cnpj_e_validade():
    cert = adn.abrir_pfx(pfx(), SENHA)
    assert cert.cnpj == CNPJ_A and cert.validade > datetime.now(timezone.utc)


@pytest.mark.parametrize("dados,senha", [(pfx(), "errada"), (b"nao e pfx", SENHA)])
def test_abrir_pfx_recusa_senha_errada_e_arquivo_invalido(dados, senha):
    with pytest.raises(adn.ErroCertificado):
        adn.abrir_pfx(dados, senha)


def test_abrir_pfx_recusa_e_cpf():
    with pytest.raises(adn.ErroCertificado):
        adn.abrir_pfx(pfx(cn="PESSOA FICTICIA:12345678909"), SENHA)


def _espiar_load_cert_chain(monkeypatch, falhar: bool):
    vistos = []
    original = ssl.SSLContext.load_cert_chain

    def espiao(self, certfile, keyfile=None, password=None):
        dados = Path(keyfile).read_bytes()
        vistos.append((Path(keyfile).parent, dados))
        with pytest.raises(TypeError):  # cifrada: nao abre sem a senha de uso unico
            serialization.load_pem_private_key(dados, password=None)
        if falhar:
            raise ssl.SSLError("falha injetada")
        return original(self, certfile, keyfile, password)

    monkeypatch.setattr(ssl.SSLContext, "load_cert_chain", espiao)
    return vistos


def test_chave_no_temporario_vai_cifrada_e_some(monkeypatch):
    vistos = _espiar_load_cert_chain(monkeypatch, falhar=False)
    adn.contexto_tls(adn.abrir_pfx(pfx(), SENHA))
    pasta, dados = vistos[0]
    assert b"ENCRYPTED PRIVATE KEY" in dados and SENHA.encode() not in dados
    assert not pasta.exists()


def test_temporario_some_quando_a_carga_falha(monkeypatch):
    vistos = _espiar_load_cert_chain(monkeypatch, falhar=True)
    with pytest.raises(ssl.SSLError):
        adn.contexto_tls(adn.abrir_pfx(pfx(), SENHA))
    assert not vistos[0][0].exists()


# ---------- servidor TLS local ----------

def _cert_local(tmp_path):
    k = ec.generate_private_key(ec.SECP256R1())
    nome = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    agora = datetime.now(timezone.utc)
    c = (x509.CertificateBuilder().subject_name(nome).issuer_name(nome).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(agora - timedelta(days=1))
         .not_valid_after(agora + timedelta(days=1))
         .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
         .sign(k, hashes.SHA256()))
    cert, chave = tmp_path / "srv.pem", tmp_path / "srv.key"
    cert.write_bytes(c.public_bytes(serialization.Encoding.PEM))
    chave.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    return cert, chave


@pytest.fixture
def servidor(tmp_path):
    """Responde conforme `resp` e conta conexoes e requisicoes."""
    estado = {"conexoes": 0, "caminhos": [], "resp": (200, {}, b"{}")}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            estado["caminhos"].append((self.command, self.path))
            status, cab, corpo = estado["resp"]
            self.send_response(status)
            for k, v in cab.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(corpo)))
            self.end_headers()
            self.wfile.write(corpo)

        def log_message(self, *a):
            pass

    class S(http.server.HTTPServer):
        def get_request(self):
            estado["conexoes"] += 1
            return super().get_request()

    cert, chave = _cert_local(tmp_path)
    srv = S(("127.0.0.1", 0), H)
    ctx_srv = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx_srv.load_cert_chain(cert, chave)
    srv.socket = ctx_srv.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    ctx_cli = ssl.create_default_context(cafile=str(cert))
    porta = srv.server_address[1]

    def conexao(host, porta_pedida, context=None, timeout=None):
        # transporte real (HTTPSConnection); so o destino TCP vai ao servidor local
        assert host in adn.HOSTS and porta_pedida == 443
        return http.client.HTTPSConnection("127.0.0.1", porta, context=ctx_cli, timeout=5)

    estado["conexao"] = conexao
    yield estado
    srv.shutdown()


def test_get_pede_o_caminho_do_adn_e_le_o_lote(servidor):
    servidor["resp"] = (200, {}, json_bytes({"LoteDFe": [{"NSU": 1}], "StatusProcessamento": "X"}))
    pag = adn.obter_pagina(None, CNPJ_A, 0, conexao=servidor["conexao"])
    assert (pag.status, pag.itens) == (200, [{"NSU": 1}])
    assert servidor["caminhos"] == [("GET", f"/contribuintes/DFe/0?lote=true&cnpjConsulta={CNPJ_A}")]


@pytest.mark.parametrize("status", [404, 429, 400])
def test_status_volta_como_veio(servidor, status):
    servidor["resp"] = (status, {"Retry-After": "60"} if status == 429 else {}, b"{}")
    pag = adn.obter_pagina(None, CNPJ_A, 5, conexao=servidor["conexao"])
    assert (pag.status, pag.itens) == (status, [])


@pytest.mark.parametrize("codigo", [301, 302, 307])
def test_redirecionamento_e_erro_sem_segunda_conexao(servidor, codigo):
    servidor["resp"] = (codigo, {"Location": "http://outro.exemplo/roubo"}, b"")
    with pytest.raises(adn.ErroRede):
        adn.obter_pagina(None, CNPJ_A, 0, conexao=servidor["conexao"])
    assert (servidor["conexoes"], len(servidor["caminhos"])) == (1, 1)


@pytest.mark.parametrize("host,porta", [("outro.exemplo", 443), ("http://adn.nfse.gov.br", 443),
                                        ("adn.nfse.gov.br", 80), ("adn.nfse.gov.br", 8443),
                                        ("adn.nfse.gov.br.exemplo", 443)])
def test_guarda_recusa_antes_de_conectar(servidor, host, porta):
    with pytest.raises(adn.ErroRede):
        adn.obter_pagina(None, CNPJ_A, 0, host=host, porta=porta, conexao=servidor["conexao"])
    assert servidor["conexoes"] == 0


@pytest.mark.parametrize("corpo", [{"LoteDFe": None}, {"StatusProcessamento": "NENHUM_DOCUMENTO_LOCALIZADO"}, {}])
def test_200_sem_lote_vale_lote_vazio(servidor, corpo):
    servidor["resp"] = (200, {}, json_bytes(corpo))
    assert adn.obter_pagina(None, CNPJ_A, 0, conexao=servidor["conexao"]).itens == []


def test_corpo_fora_do_formato_e_erro(servidor):
    servidor["resp"] = (200, {}, b"<html>nao e json</html>")
    with pytest.raises(adn.ErroRede):
        adn.obter_pagina(None, CNPJ_A, 0, conexao=servidor["conexao"])


def test_so_metodo_get_no_modulo():
    fonte = (Path(adn.__file__)).read_text(encoding="utf-8")
    assert fonte.count('con.request("GET"') == 1
    for metodo in ("POST", "PUT", "DELETE", "PATCH"):
        assert f'"{metodo}"' not in fonte


def test_so_o_adn_importa_rede():
    motor = Path(adn.__file__).resolve().parent.parent
    # so o programa (o escopo do cheque sem rede): na raiz publica tambem ha ferramentas/ e, as vezes, um .venv
    programa = [motor / "capturador.py", *(motor / "engine").rglob("*.py")]
    com_rede = sorted(str(p.relative_to(motor)).replace("\\", "/") for p in programa
                      if re.search(r"\b(urllib|ssl|http\.client|socket|requests)\b", p.read_text(encoding="utf-8")))
    assert com_rede == ["engine/adn.py", "engine/guarda.py"]
    # o guarda so resolve o host do ADN (para conferir o IP do connect); nunca conecta nem envia
    arvore = ast.parse((motor / "engine" / "guarda.py").read_text(encoding="utf-8"))
    usos = {n.attr for n in ast.walk(arvore) if isinstance(n, ast.Attribute)
            and isinstance(n.value, ast.Name) and n.value.id == "socket"}
    assert usos == {"getaddrinfo", "IPPROTO_TCP"}
