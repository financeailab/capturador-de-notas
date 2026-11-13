"""Casos do guarda em processo novo: GUARDA_SENTINELA=<arquivo> python tests/casos_guarda.py <caso>.

O guarda e instalado antes de importar terceiro, como no capturador.py. Nos casos de ataque (V1) a carga tenta criar
o arquivo sentinela; o teste exige rc 4 e o sentinela ausente. Os demais (V3, V8, V9) imprimem uma linha 'ok ...'.
"""
import os
import sys
from pathlib import Path

MOTOR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(MOTOR))

from engine import guarda  # noqa: E402

guarda.instalar(MOTOR / "capturador.py")

CASO, SENT = sys.argv[1], os.environ["GUARDA_SENTINELA"]
CARGA = "__import__('os').system('echo x> ' + __import__('os').environ['GUARDA_SENTINELA'])"
S_CARGA = CARGA + " or int"
CHAVE = "_" * 2 + "annotations" + "_" * 2


def modelo(anotacao):
    from pydantic import BaseModel
    return type("M", (BaseModel,), {CHAVE: {"x": anotacao}})


def caso_01():
    from pydantic import BaseModel

    class M(BaseModel):
        x: "__import__('os').system('echo x> ' + __import__('os').environ['GUARDA_SENTINELA'])"


def caso_02():
    from pydantic import BaseModel

    class M(BaseModel):
        x: S_CARGA


def caso_03():
    t = type
    from pydantic import BaseModel
    t("M", (BaseModel,), {CHAVE: {"x": CARGA + " or int"}})


def caso_04():
    from pydantic import BaseModel
    (1).__class__.__class__("M", (BaseModel,), {CHAVE: {"x": CARGA + " or int"}})


def caso_05():
    eval(CARGA)


def caso_06():
    lib = "'msvcrt'" if os.name == "nt" else ("'libc.so.6'" if sys.platform.startswith("linux") else "None")
    eval("__import__('_cffi_backend').load_library(" + lib + ")")


def caso_07():
    os.system("echo x> " + SENT)


def caso_08():
    import subprocess
    cmd = ["cmd", "/c", "echo x> " + SENT] if os.name == "nt" else ["sh", "-c", "echo x> '" + SENT + "'"]
    subprocess.run(cmd)


def caso_09():
    import subprocess
    subprocess.run(["schtasks", "/Create", "/F", "/SC", "DAILY", "/TN", "capturador-de-notas-0123abcd",
                    "/ST", "06:00", "/TR", "cmd /c echo x> " + SENT])


def caso_10():
    import socket
    socket.create_connection(("example.com", 443), timeout=5)


def caso_11():
    import socket
    socket.getaddrinfo("dados.exemplo.invalid", 443)


def caso_12():
    import socket
    socket.create_connection(("1.1.1.1", 443), timeout=5)


def caso_13():
    modelo("lambda: " + CARGA)(x={})


def caso_14():
    modelo("(int, lambda: " + CARGA + ")[1]")(x={})


def caso_15():
    modelo("(HOSTS := 1) and int")


def caso_16():
    # biblioteca nativa carregada por atributo, sem chamada: a regra 1 deixa passar (medido), a regra nativa pega.
    import ctypes
    biblioteca = "msvcrt" if os.name == "nt" else "c"
    eval(compile("ctypes.cdll." + biblioteca + " and 1", "<carga>", "eval"), {"ctypes": ctypes})


def caso_legitimo_rede():
    import http.client
    import ssl
    from engine import adn
    from tests.sinteticos import CNPJ_A
    porta = int(os.environ["GUARDA_PORTA"])
    guarda.HOSTS, guarda.PORTA = ("localhost",), porta  # so no teste: o servidor local faz o papel do ADN
    ctx = ssl.create_default_context(cafile=os.environ["GUARDA_CA"])

    def conexao(host):
        return lambda _h, _p, context=None, timeout=None: http.client.HTTPSConnection(host, porta, context=ctx,
                                                                                       timeout=5)

    print("ok rede", adn.obter_pagina(None, CNPJ_A, 0, conexao=conexao("localhost")).status, flush=True)
    adn.obter_pagina(None, CNPJ_A, 0, conexao=conexao("127.0.0.1"))
    print("FALHOU: 127.0.0.1 passou")


def caso_legitimo_reresolver():
    import socket
    porta = int(os.environ["GUARDA_PORTA"])
    guarda.HOSTS, guarda.PORTA = ("localhost",), porta  # so no teste
    s = socket.socket()
    s.connect(("127.0.0.1", porta))  # sem DNS antes: o IP nao esta no acumulado, o guarda resolve de novo e aceita
    s.close()
    print("ok reresolver", flush=True)
    socket.socket().connect(("127.0.0.2", porta))
    print("FALHOU: 127.0.0.2 passou")


def caso_pegajoso_eval():
    try:
        os.system("echo x> " + SENT)
    except BaseException:
        pass
    eval("1")
    print("FALHOU: eval depois do bloqueio passou")


def caso_pegajoso_main(depois):
    import capturador

    def baixar_que_engole(_pasta):
        try:
            os.system("echo x> " + SENT)
        except BaseException:
            pass
        if depois == "erro":
            raise ValueError("depois do bloqueio")
        return 0

    capturador.baixar = baixar_que_engole
    sys.argv = ["capturador.py", "baixar", "--pasta", str(Path(SENT).parent)]
    print("ok main", capturador.main())


def caso_legitimo_baixar():
    import capturador
    from engine import adn
    from tests.sinteticos import CNPJ_A, SENHA, ADNFalso, envelope, nfse_xml, pfx
    import keyring.backend

    class Cofre(keyring.backend.KeyringBackend):
        priority = 1
        dados = {}

        def set_password(self, s, u, p):
            self.dados[(s, u)] = p

        def get_password(self, s, u):
            return self.dados.get((s, u))

        def delete_password(self, s, u):
            self.dados.pop((s, u), None)

    import keyring
    keyring.set_keyring(Cofre())
    pasta = Path(SENT).parent / "notas"
    pasta.mkdir()
    caminho_pfx = Path(SENT).parent / "a.pfx"
    caminho_pfx.write_bytes(pfx(CNPJ_A))
    capturador.getpass.getpass = lambda _p: SENHA
    print("ok configurar", capturador.configurar(pasta, CNPJ_A, str(caminho_pfx)))
    falso = ADNFalso({CNPJ_A: [envelope(i, nfse_xml(i)) for i in range(1, 4)]})
    adn.contexto_tls = lambda cert: None
    adn.obter_pagina = lambda ctx, cnpj, nsu: falso(cnpj, nsu)
    print("ok baixar", capturador.baixar(pasta), len(list(pasta.rglob("*.xml"))))


def caso_legitimo_cofre():
    import keyring
    import keyring.errors
    try:
        valor = keyring.get_password("capturador-de-notas", "inexistente-guarda-v3")
    except keyring.errors.NoKeyringError:  # CI Linux sem Secret Service: sem cofre, mas o guarda nao bloqueou
        valor = "sem cofre"
    print("ok cofre", valor)


def caso_concorrencia():
    """Enquanto uma thread passa pelo hook (DNS), o evento proibido de outra thread nunca passa sem a politica."""
    import socket
    import threading
    import time
    guarda.HOSTS = ("localhost",)  # so no teste: DNS local, sem rede
    sys.setswitchinterval(1e-6)
    fim = time.monotonic() + 1

    def dns():
        while time.monotonic() < fim:
            try:
                socket.getaddrinfo("localhost", guarda.PORTA)
            except BaseException:
                pass

    t = threading.Thread(target=dns)
    t.start()
    passaram = 0
    while time.monotonic() < fim:
        try:
            sys.audit("os.system", b"echo")  # so o evento: nenhum comando roda
            passaram += 1
        except SystemExit:
            pass
    t.join()
    print("ok concorrencia", passaram)


def caso_limpar_dict():
    # texto sem chamada alcanca o __dict__ do modulo do guarda e o chamador (aqui, como o Pydantic faria) o invoca
    # sem argumento. O guarda nao bloqueia com rc 4, mas o hook passa a falhar (NameError) e aborta todo evento
    # seguinte: falha fechada por queda, nao bypass. os.write(2, ...) nao gera evento e funciona ate depois do clear.
    import engine.guarda as g
    os.write(2, b"antes do clear\n")  # prova que a regra 1 nao bloqueou o texto sem chamada
    limpar = eval(compile("g.__dict__.clear", "<carga>", "eval"), {"g": g})  # texto sem CALL (medido)
    limpar()
    try:
        os.system("echo x> " + SENT)  # nunca cria o sentinela: o hook sem estado aborta o evento
    except BaseException:
        pass
    os.write(2, b"sentinela existe: " + str(os.path.exists(SENT)).encode() + b"\n")


def caso_pydantic_nativo():
    # BLOQUEIA do gate adversarial: a anotacao-texto nomeia um carregador nativo (so LOAD_ATTR, passa a regra 1); o
    # Pydantic monta um call-schema e chama LoadLibrary(valor) do quadro DELE, sem texto na pilha nem import. Antes
    # escapava da regra nativa (que so olhava texto na pilha); agora a regra nativa so libera durante import. rc 4.
    import ctypes  # noqa: F401  (nome que a anotacao-texto "ctypes.cdll.LoadLibrary" resolve no namespace do modulo)
    from pydantic import BaseModel
    M = type("M", (BaseModel,), {CHAVE: {"x": "ctypes.cdll.LoadLibrary"}})
    M(x=("biblioteca-inexistente-guarda",))
    print("FALHOU: carga nativa via Pydantic passou")


def caso_pydantic_nativo_cwfr():
    # BLOQUEIA do Codex (forja do quadro de import): _call_with_frames_removed roda um callable COM um quadro
    # <frozen importlib> na pilha, sem importar nada. O Pydantic chama o trampolim via call-schema, com o carregador
    # nativo e o arg vindos do input. Antes, _na_importacao via o quadro frozen e liberava a carga; agora exige um
    # DRIVER real de import (_carga_no_import), que a forja nao tem. rc 4. (anotacao = objeto: testa o guarda, nao a
    # resolucao de forward-ref do Pydantic, ja coberta por caso_pydantic_nativo.)
    import ctypes
    from importlib._bootstrap import _call_with_frames_removed
    from pydantic import BaseModel
    M = type("M", (BaseModel,), {CHAVE: {"x": _call_with_frames_removed}})
    M(x=(ctypes.cdll.LoadLibrary, "biblioteca-inexistente-guarda"))
    print("FALHOU: forja de quadro de import carregou lib nativa")


def caso_pydantic_nativo_fal():
    # BLOQUEIA do Codex (forja por callback do driver): _find_and_load(nome, import_) chama import_(pai). O input traz
    # import_ = o carregador nativo, pondo _find_and_load (um "driver") na pilha ao disparar a carga. Fechado tirando
    # _find_and_load[_unlocked] do conjunto de drivers (recebem callback). rc 4.
    import ctypes
    from importlib._bootstrap import _find_and_load
    from pydantic import BaseModel
    M = type("M", (BaseModel,), {CHAVE: {"x": _find_and_load}})
    M(x=("pacote_inexistente_guarda.sub", ctypes.cdll.LoadLibrary))
    print("FALHOU: forja por callback de driver carregou lib nativa")


def caso_agendar():
    import capturador
    capturador._ler_config = lambda p: {"empresas": []}

    def corta(evento, _args):
        if evento == "_winapi.CreateProcess":
            raise RuntimeError("cortado")

    sys.addaudithook(corta)
    for pasta in (Path(SENT).parent, Path(Path(SENT).anchor), Path(SENT).parent / "com espaco"):
        try:
            capturador.agendar(pasta, "06:00")
        except RuntimeError:
            print("ok agendar", len(str(pasta)))


CASOS = {n[5:]: f for n, f in list(globals().items()) if n.startswith("caso_") and n[5:7].isdigit()}
CASOS.update({"pegajoso_eval": caso_pegajoso_eval, "pegajoso_main": lambda: caso_pegajoso_main("zero"),
              "pegajoso_main_erro": lambda: caso_pegajoso_main("erro"), "legitimo_baixar": caso_legitimo_baixar,
              "legitimo_cofre": caso_legitimo_cofre, "legitimo_rede": caso_legitimo_rede,
              "legitimo_reresolver": caso_legitimo_reresolver, "concorrencia": caso_concorrencia,
              "limpar_dict": caso_limpar_dict, "agendar": caso_agendar, "pydantic_nativo": caso_pydantic_nativo,
              "pydantic_nativo_cwfr": caso_pydantic_nativo_cwfr, "pydantic_nativo_fal": caso_pydantic_nativo_fal})
CASOS[CASO]()
