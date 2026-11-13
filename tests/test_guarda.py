"""Guarda em tempo de execucao: politica pura (V2) e casos em processo novo (V1, V3, V8, V9)."""
from __future__ import annotations

import hashlib
import http.server
import ipaddress
import os
import ssl
import subprocess
import sys
import threading
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from engine import adn, guarda

MOTOR = Path(guarda.__file__).resolve().parent.parent
CASOS = MOTOR / "tests" / "casos_guarda.py"
CAP = str(MOTOR / "capturador.py")
ATAQUES = [f"{i:02d}" for i in range(1, 17)]


def rodar(caso, tmp_path, **env_extra):
    sent = tmp_path / "sentinela.txt"
    env = {**os.environ, "GUARDA_SENTINELA": str(sent), "PYTHONPATH": str(MOTOR), **env_extra}
    r = subprocess.run([sys.executable, str(CASOS), caso], capture_output=True, text=True, timeout=120,
                       stdin=subprocess.DEVNULL, env=env, cwd=MOTOR)
    return r, sent


@pytest.mark.parametrize("caso", ATAQUES)
def test_aceite_barra_com_rc_4_sem_efeito_nem_texto_da_carga(caso, tmp_path):
    r, sent = rodar(caso, tmp_path)
    assert r.returncode == 4, (caso, r.returncode, r.stderr[-300:])
    assert "guarda: bloqueou" in r.stderr
    assert not sent.exists()
    assert str(sent) not in r.stderr + r.stdout and "echo" not in r.stderr + r.stdout


def test_pegajoso_eval_depois_do_bloqueio_engolido_barra(tmp_path):
    r, sent = rodar("pegajoso_eval", tmp_path)
    assert r.returncode == 4 and "FALHOU" not in r.stdout and not sent.exists()


@pytest.mark.parametrize("caso", ["pegajoso_main", "pegajoso_main_erro"])
def test_pegajoso_main_devolve_4_com_a_trava_ligada(caso, tmp_path):
    r, sent = rodar(caso, tmp_path)
    assert "ok main 4" in r.stdout, (r.returncode, r.stdout, r.stderr[-300:])
    assert not sent.exists()


def test_legitimo_baixar_com_o_guarda(tmp_path):
    r, _ = rodar("legitimo_baixar", tmp_path)
    assert "guarda: bloqueou" not in r.stderr, r.stderr[-300:]
    assert "ok configurar 0" in r.stdout and "ok baixar 0 3" in r.stdout, r.stdout


@pytest.mark.parametrize("caso", ["pydantic_nativo", "pydantic_nativo_cwfr", "pydantic_nativo_fal"])
def test_pydantic_call_schema_nativo_barrado(caso, tmp_path):
    r, sent = rodar(caso, tmp_path)
    assert r.returncode == 4 and "guarda: bloqueou nativo" in r.stderr, (r.returncode, r.stdout, r.stderr[-300:])
    assert "FALHOU" not in r.stdout and not sent.exists()


def test_pydantic_recusa_chamada_nativa_crua_tripwire():
    # Tripwire (ENDURECE Fable): a chamada nativa crua escaparia de TODO chokepoint do guarda (memmove/memset = escrita
    # de memoria; um _FuncPtr ja resolvido = chamada direta de simbolo) porque nao emite evento de audit. So nao e
    # alcancavel porque o Pydantic recusa esses callables como call-schema (CFunctionType / _FuncPtr). Se um Pydantic
    # futuro passar a aceita-los, ISTO falha e avisa que o guarda precisa cobrir isso. Par com o pino pydantic<3.
    import ctypes
    from pydantic import BaseModel
    crus = [ctypes.memmove, ctypes.memset, ctypes.pythonapi.Py_IsInitialized]  # CFunctionType + _FuncPtr resolvido
    for fn in crus:
        with pytest.raises(Exception):
            type("Mx", (BaseModel,), {"__annotations__": {"x": fn}})


def test_legitimo_cofre_com_chave_inexistente(tmp_path):
    r, _ = rodar("legitimo_cofre", tmp_path)
    assert r.returncode == 0 and "guarda: bloqueou" not in r.stderr and "ok cofre" in r.stdout, r.stderr[-300:]


def _cert(tmp_path):
    k = ec.generate_private_key(ec.SECP256R1())
    nome = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    agora = datetime.now(timezone.utc)
    san = x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
    c = (x509.CertificateBuilder().subject_name(nome).issuer_name(nome).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(agora - timedelta(days=1))
         .not_valid_after(agora + timedelta(days=1)).add_extension(san, False).sign(k, hashes.SHA256()))
    cert, chave = tmp_path / "srv.pem", tmp_path / "srv.key"
    cert.write_bytes(c.public_bytes(serialization.Encoding.PEM))
    chave.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    return cert, chave


def rodar_com_servidor(caso, tmp_path):
    """Roda o caso com um servidor HTTPS local (404 para tudo) no papel do ADN."""
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    class S(http.server.HTTPServer):
        def handle_error(self, *a):  # o caso que so abre o TCP fecha sem TLS; nao e falha do teste
            pass

    cert, chave = _cert(tmp_path)
    srv = S(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, chave)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        return rodar(caso, tmp_path, GUARDA_PORTA=str(srv.server_address[1]), GUARDA_CA=str(cert))[0]
    finally:
        srv.shutdown()


def test_legitimo_rede_real_com_o_guarda(tmp_path):
    """getaddrinfo, a resolucao do proprio guarda, socket.connect e http.client.connect de verdade."""
    r = rodar_com_servidor("legitimo_rede", tmp_path)
    assert "ok rede 404" in r.stdout, (r.stdout, r.stderr[-300:])
    assert r.returncode == 4 and "guarda: bloqueou rede" in r.stderr  # 127.0.0.1 nao e host permitido


def test_legitimo_connect_fora_do_acumulado_resolve_de_novo(tmp_path):
    r = rodar_com_servidor("legitimo_reresolver", tmp_path)
    assert "ok reresolver" in r.stdout, (r.stdout, r.stderr[-300:])
    assert r.returncode == 4 and "guarda: bloqueou rede" in r.stderr and "FALHOU" not in r.stdout


def test_concorrencia_evento_proibido_de_outra_thread_nunca_passa(tmp_path):
    r, _ = rodar("concorrencia", tmp_path)
    assert "ok concorrencia 0" in r.stdout, (r.stdout, r.stderr[-300:])


def test_limpar_o_dict_do_guarda_falha_fechado(tmp_path):
    r, sent = rodar("limpar_dict", tmp_path)
    assert "antes do clear" in r.stderr  # a regra 1 nao bloqueou o texto sem chamada; o clear rodou
    assert "sentinela existe: False" in r.stderr, (r.stdout, r.stderr[-300:])
    assert not sent.exists()  # sem rc 4, mas o evento proibido nao roda: nada vaza


@pytest.mark.skipif(os.name != "nt", reason="o agendar so cria processo no Windows")
def test_agendar_real_ate_o_createprocess(tmp_path):
    (tmp_path / "com espaco").mkdir()
    r, _ = rodar("agendar", tmp_path)
    assert "guarda: bloqueou" not in r.stderr, r.stderr[-300:]
    assert r.stdout.count("ok agendar") == 3, r.stdout


# V2: a politica pura


def estado(trava=False, ficha=False, cap=CAP, dbus=(), ips=()):
    return (trava, ficha, cap, tuple(dbus), frozenset(ips))


def texto(fonte, modo="eval"):
    return compile(fonte, "<string>", modo)


def test_decidir_hosts_e_a_mesma_lista_do_adn():
    assert guarda.HOSTS == adn.HOSTS and guarda.PORTA == adn.PORTA


def test_estado_do_guarda_so_tem_valor_imutavel():
    mutaveis = {n: type(v).__name__ for n, v in vars(guarda).items()
                if not n.startswith("__") and isinstance(v, (dict, list, set, bytearray))}
    assert mutaveis == {}


@pytest.mark.parametrize("args,esperado", [
    (("adn.nfse.gov.br", 443), "resolver"), (("ADN.NFSE.GOV.BR.", "443"), "resolver"),
    ((b"adn.producaorestrita.nfse.gov.br", 443), "resolver"), (("adn.nfse.gov.br", 80), "rede"),
    (("adn.nfse.gov.br.evil", 443), "rede"), ((None, 443), "rede"), (("1.1.1.1", 443), "rede"),
])
def test_decidir_dns(args, esperado):
    assert guarda.decidir("socket.getaddrinfo", args, estado=estado()) == esperado


def test_decidir_connect_so_ip_resolvido_na_443_e_dbus():
    e = estado(ips={"10.0.0.1", "::1"}, dbus=("/run/user/1/bus", "\0/tmp/dbus-x"))
    assert guarda.decidir("socket.connect", (None, ("10.0.0.1", 443)), estado=e) is None
    assert guarda.decidir("socket.connect", (None, ("::1", 443, 0, 0)), estado=e) is None
    assert guarda.decidir("socket.connect", (None, ("10.0.0.1", 80)), estado=e) == "rede"
    assert guarda.decidir("socket.connect", (None, ("10.0.0.2", 443)), estado=e) == "rede"
    assert guarda.decidir("socket.connect", (None, "/run/user/1/bus"), estado=e) is None
    assert guarda.decidir("socket.connect", (None, b"\0/tmp/dbus-x"), estado=e) is None
    assert guarda.decidir("socket.connect", (None, "/tmp/outro"), estado=e) == "rede"
    assert guarda.decidir("socket.connect", (None, "/run/user/1/bus"), estado=estado()) == "rede"


@pytest.mark.parametrize("valor,esperado", [
    ("unix:path=/run/user/1000/bus", ("/run/user/1000/bus",)),
    ("unix:path=/run/user/1000/bus,guid=abc", ("/run/user/1000/bus",)),
    ("unix:abstract=/tmp/dbus-XYZ,guid=abc", ("\0/tmp/dbus-XYZ",)),
    ("tcp:host=localhost,port=1;unix:path=/a", ("/a",)),
    ("unix:path=/run/user/1000/b%20us", ()), ("", ()), ("unix:tmpdir=/tmp", ()),
])
def test_enderecos_dbus(valor, esperado):
    assert guarda.enderecos_dbus(valor) == esperado


@pytest.mark.parametrize("arg", ['C:\\pasta\\notas', 'C:\\', 'C:\\com espaco\\x', 'C:\\a\\\\', 'sem"aspas'])
def test_aspas_igual_ao_list2cmdline(arg):
    assert guarda._aspas(arg + ' x') == subprocess.list2cmdline([arg + ' x'])


def linha(pasta, hora="06:00", trocar=None):
    fim = "\\" if pasta.endswith("\\") else ""
    lista = ["schtasks", "/Create", "/F", "/SC", "DAILY", "/TN",
             "capturador-de-notas-" + hashlib.sha256(pasta.lower().encode()).hexdigest()[:8],
             "/ST", hora, "/TR", f'"{sys.executable}" "{CAP}" baixar --pasta "{pasta}{fim}"']
    for i, v in (trocar or {}).items():
        lista[i] = v
    return subprocess.list2cmdline(lista)


@pytest.mark.skipif(os.name != "nt", reason="o Popen so passa no Windows")
@pytest.mark.parametrize("pasta", ["C:\\notas", "D:\\", "C:\\com espaco\\notas", "C:\\Notas Maiusc"])
def test_decidir_popen_aceita_a_linha_reconstruida(pasta):
    assert guarda.decidir("subprocess.Popen", (None, linha(pasta), None, None), estado=estado()) == "ficha"


@pytest.mark.skipif(os.name != "nt", reason="o Popen so passa no Windows")
@pytest.mark.parametrize("args", [
    (None, linha("C:\\n", trocar={1: "/Query"}), None, None),
    (None, linha("C:\\n", trocar={10: "cmd /c calc"}), None, None),
    (None, linha("C:\\n", trocar={6: "capturador-de-notas-0123abcd"}), None, None),
    (None, linha("C:\\n") + " /S outro", None, None),
    (None, linha("C:\\n", hora="25:00"), None, None),
    ("schtasks.exe", linha("C:\\n"), None, None),
    (None, linha("C:\\n"), "C:\\", None),
    (None, linha("C:\\n"), None, {"PATH": "x"}),
    (None, ["schtasks", "/Create"], None, None),
    (None, "", None, None),
])
def test_decidir_popen_barra_o_resto(args):
    assert guarda.decidir("subprocess.Popen", args, estado=estado()) == "processo"


def test_decidir_popen_barra_sem_capturador_instalado():
    assert guarda.decidir("subprocess.Popen", (None, linha("C:\\n"), None, None), estado=estado(cap="")) == "processo"


def test_decidir_popen_fora_do_windows_barra(monkeypatch):
    monkeypatch.setattr(guarda, "os", types.SimpleNamespace(name="posix", sep="/", path=os.path, environ={}))
    assert guarda.decidir("subprocess.Popen", (None, linha("C:\\n"), None, None), estado=estado()) == "processo"


def quadro_falso(frames):
    """Encadeia (co_filename, co_name) do mais interno (onde o walk comeca) ao mais externo, via f_back."""
    prox = None
    for fn, nome in reversed(frames):
        prox = types.SimpleNamespace(f_code=types.SimpleNamespace(co_filename=fn, co_name=nome), f_back=prox)
    return prox


def test_do_find_library_so_pelo_ctypes_util_sem_texto():
    util = "/opt/py/lib/python3.12/ctypes/util.py"
    sub = "/opt/py/lib/python3.12/subprocess.py"
    # ldconfig/gcc disparados pela maquinaria do ctypes.util: libera
    assert guarda._do_find_library(quadro_falso([(sub, "_execute_child"), (sub, "__init__"),
                                                 (util, "_findSoname_ldconfig"), ("x/casos.py", "c")])) is True
    assert guarda._do_find_library(quadro_falso([(sub, "_execute_child"), (util, "_findLib_gcc")])) is True
    # chamada de ataque direta, sem o ctypes.util no caminho: nao libera
    assert guarda._do_find_library(quadro_falso([(sub, "_execute_child"), (sub, "run"),
                                                 ("x/casos.py", "caso_08")])) is False
    # texto no caminho antes do ctypes.util: nao libera
    assert guarda._do_find_library(quadro_falso([("<carga>", "<module>"),
                                                 (util, "_findSoname_ldconfig")])) is False
    # ENDURECE: texto ACIMA do quadro do ctypes.util (mais externo) tambem barra (varredura da pilha inteira)
    assert guarda._do_find_library(quadro_falso([(sub, "_execute_child"), (util, "_findLib_gcc"),
                                                 ("<carga>", "<module>")])) is False
    # funcao do ctypes.util que nao cria processo: nao libera
    assert guarda._do_find_library(quadro_falso([(sub, "_execute_child"), (util, "test_find_library")])) is False


def test_decidir_popen_find_lib_libera_so_sem_trava():
    cmd = ["/sbin/ldconfig", "-p"]
    assert guarda.decidir("subprocess.Popen", (None, cmd, None, None), estado=estado(), find_lib=True) is None
    assert guarda.decidir("subprocess.Popen", (None, cmd, None, None), estado=estado(), find_lib=False) == "processo"
    assert guarda.decidir("subprocess.Popen", (None, cmd, None, None), estado=estado(trava=True), find_lib=True) == "trava"


SUBPROCESSO = ("/subprocess.py", "_execute_child")


def test_decidir_ficha_do_createprocess_so_pelo_subprocess():
    cp = "_winapi.CreateProcess"
    assert guarda.decidir(cp, (None, "x", None), SUBPROCESSO, estado(ficha=True)) == "gastar"
    assert guarda.decidir(cp, (None, "x", None), SUBPROCESSO, estado()) == "processo"
    assert guarda.decidir(cp, (None, "x", None), ("C:/x/ataque.py", "f"), estado(ficha=True)) == "processo"
    assert guarda.decidir(cp, (None, "x", None), ("/subprocess.py", "outra"), estado(ficha=True)) == "processo"


@pytest.mark.parametrize("arquivo,esperado", [
    ("C:\\Python312\\Lib\\collections\\__init__.py", "/collections/__init__.py"),
    ("C:/Python312/Lib/collections/__init__.py", "/collections/__init__.py"),
    ("/usr/lib/python3.12/subprocess.py", "/subprocess.py"),
    ("C:\\x\\mydataclasses.py", "C:/x/mydataclasses.py"),
])
def test_quem_normaliza_a_barra(arquivo, esperado):
    quadro = types.SimpleNamespace(f_code=types.SimpleNamespace(co_filename=arquivo, co_name="f"))
    assert guarda._quem(quadro) == (esperado, "f")


def test_decidir_regra_1_texto():
    e = estado()
    assert guarda.decidir("exec", (texto("int | None"),), ("x", "f"), e) is None
    assert guarda.decidir("exec", (texto("abs(1)"),), ("x", "f"), e) == "texto"
    assert guarda.decidir("exec", (texto("lambda: abs(1)"),), ("x", "f"), e) == "texto"
    assert guarda.decidir("exec", (texto("(int, lambda: abs(1))[1]"),), ("x", "f"), e) == "texto"
    assert guarda.decidir("exec", (texto("(n := 1)"),), ("x", "f"), e) == "texto"
    assert guarda.decidir("exec", (texto("def f():\n    global g\n    g = 1\n", "exec"),), ("x", "f"), e) == "texto"
    for fonte in ("m.x = 1", "del m.x", "m[0] = 1", "del m[0]", "m[0:1] = []", "import os", "from os import sep"):
        assert guarda.decidir("exec", (texto(fonte, "exec"),), ("x", "f"), e) == "texto", fonte
    assert guarda.decidir("exec", (texto("[i for i in m]"),), ("x", "f"), e) is None  # so variavel local
    gerador = ("/collections/__init__.py", "namedtuple")
    assert guarda.decidir("exec", (texto("lambda a: abs(a)"),), gerador, e) is None
    assert guarda.decidir("exec", (texto("lambda a: abs(a)"),), (gerador[0], "outra"), e) == "texto"
    # ply vendorizado no pycparser 2.x (cffi -> keyring) carrega a tabela por exec('import yacctab'): import liberado so nesses quadros
    for ply in (("/ply/lex.py", "readtab"), ("/ply/yacc.py", "read_table")):
        assert guarda.decidir("exec", (texto("import yacctab", "exec"),), ply, e) is None, ply
        assert guarda.decidir("exec", (texto("import yacctab", "exec"),), (ply[0], "outra"), e) == "texto", ply
    assert guarda.decidir("exec", (compile("abs(1)", "x.py", "eval"),), ("x", "f"), e) is None


@pytest.mark.parametrize("evento", ["ctypes.dlopen", "ctypes.dlsym", "ctypes.dlsym/handle"])
def test_decidir_nativo_so_na_importacao(evento):
    # carga nativa liberada so no import (nativo_ok); fora do import barra, mesmo sem texto (confused-deputy do Pydantic)
    assert guarda.decidir(evento, ("x",), estado=estado(), nativo_ok=True) is None
    assert guarda.decidir(evento, ("x",), estado=estado(), nativo_ok=False) == "nativo"
    assert guarda.decidir(evento, ("x",), estado=estado(trava=True), nativo_ok=True) == "nativo"


def test_carga_no_import_so_com_driver_real_sem_texto():
    ct = "/opt/py/lib/python3.12/ctypes/__init__.py"
    boot = "<frozen importlib._bootstrap>"
    bext = "<frozen importlib._bootstrap_external>"
    # carga durante import real: ha quadro de DRIVER (exec_module) -> libera
    assert guarda._carga_no_import(quadro_falso([(ct, "__init__"), (ct, "<module>"), (bext, "exec_module")])) is True
    assert guarda._carga_no_import(quadro_falso([(ct, "__init__"), (boot, "_load_unlocked")])) is True
    # FORJA (BLOQUEIA do Codex): so o trampolim _call_with_frames_removed, sem driver real -> barra
    assert guarda._carga_no_import(quadro_falso([(ct, "__init__"), (boot, "_call_with_frames_removed"),
                                                 ("x/dep.py", "<module>")])) is False
    # chamada em validacao (Pydantic), sem import nenhum -> barra
    assert guarda._carga_no_import(quadro_falso([(ct, "__init__"), ("x/dep.py", "<module>")])) is False
    # texto em qualquer ponto (antes ou acima do driver) -> barra
    assert guarda._carga_no_import(quadro_falso([(ct, "__init__"), ("<carga>", "<module>"), (bext, "exec_module")])) is False
    assert guarda._carga_no_import(quadro_falso([(ct, "__init__"), (bext, "exec_module"), ("<carga>", "<module>")])) is False


def test_texto_na_pilha_varre_tudo():
    assert guarda._texto_na_pilha(quadro_falso([("x/a.py", "f"), ("<string>", "<module>")])) is True
    assert guarda._texto_na_pilha(quadro_falso([("x/a.py", "f"), ("x/b.py", "<module>")])) is False
    assert guarda._texto_na_pilha(quadro_falso([("<carga>", "<module>")])) is True


def test_decidir_trava_barra_texto_rede_e_processo():
    e = estado(trava=True, ips={"10.0.0.1"})
    assert guarda.decidir("exec", (texto("1"),), ("x", "f"), e) == "trava"
    assert guarda.decidir("socket.getaddrinfo", ("adn.nfse.gov.br", 443), estado=e) == "trava"
    assert guarda.decidir("socket.connect", (None, ("10.0.0.1", 443)), estado=e) == "trava"
    assert guarda.decidir("http.client.connect", (None, "adn.nfse.gov.br", 443), estado=e) == "trava"
    assert guarda.decidir("_winapi.CreateProcess", (None, "x", None), SUBPROCESSO, estado(trava=True, ficha=True)) == "trava"


@pytest.mark.parametrize("evento", ["os.system", "os.exec", "os.posix_spawn", "socket.bind", "socket.gethostbyaddr",
                                    "sqlite3.load_extension", "mmap.__new__", "urllib.Request"])
def test_decidir_eventos_sempre_barrados(evento):
    assert guarda.decidir(evento, ("x",), estado=estado()) == "proibido"


def test_decidir_evento_fora_da_tabela_passa():
    assert guarda.decidir("open", ("x", "r", 0), estado=estado()) is None
