# capturador-de-notas

Baixa todo dia as NFS-e que a sua empresa **emitiu e recebeu**, direto do Ambiente de Dados Nacional (ADN) da
NFS-e, para uma pasta no seu computador. A pasta ganha o XML de cada nota, organizado por mês, uma base SQLite e um
CSV pronto para abrir na planilha.

Grátis e aberto, sob Apache-2.0. É um programa de terminal em Python e roda sem IA. Mantido pelo
[Finance AI Lab](https://financeailab.com.br), um hub brasileiro de IA aplicada a Finanças Corporativas.

## O que você precisa

- Windows, macOS ou Linux, com Python 3.12 ou mais novo.
- O certificado digital A1 e-CNPJ da empresa (o arquivo `.pfx`) e a senha dele.
- Notas no padrão nacional. O capturador lê o que está no ADN: nota que o município não enviou para lá não aparece.

## Instalar

1. Baixe o [`capturador-de-notas.zip`](https://github.com/financeailab/capturador-de-notas/releases/latest/download/capturador-de-notas.zip)
   da última release e descompacte numa pasta.
2. Nessa pasta, crie um ambiente Python e instale as quatro dependências.

   Windows (PowerShell):

   ```powershell
   py -3.12 -m venv .venv
   .venv\Scripts\pip install "pydantic>=2.6" "defusedxml>=0.7.1" "cryptography>=42" "keyring>=25"
   ```

   macOS e Linux:

   ```bash
   python3.12 -m venv .venv
   .venv/bin/pip install "pydantic>=2.6" "defusedxml>=0.7.1" "cryptography>=42" "keyring>=25"
   ```

## Usar

Escolha uma pasta para as notas, fora de qualquer repositório git: o capturador recusa pasta que fica dentro de um.
Os exemplos são do Windows; no macOS e no Linux, troque `.venv\Scripts\python` por `.venv/bin/python`.

```powershell
.venv\Scripts\python capturador.py configurar --pasta C:\Notas
.venv\Scripts\python capturador.py baixar --pasta C:\Notas
.venv\Scripts\python capturador.py agendar --pasta C:\Notas --hora 09:00
```

- **`configurar`** pede o CNPJ, o caminho do `.pfx` e a senha. A senha vai para o cofre do sistema (Gerenciador de
  Credenciais no Windows, Keychain no macOS, Secret Service no Linux), nunca para arquivo nem para o comando. Rode de
  novo para cadastrar outra empresa na mesma pasta.
- **`baixar`** faz uma rodada para cada empresa cadastrada. A primeira traz o histórico; as seguintes, só o que é
  novo.
- **`agendar`** cria, no Windows, a tarefa diária no Agendador de Tarefas e imprime o nome dela. Fora do Windows,
  imprime a linha para colocar no `crontab`. A tarefa só roda com o computador ligado, então escolha uma hora em
  que ele costuma estar ligado. Dia perdido não perde nota: a rodada seguinte continua de onde a anterior parou.

## O que fica na pasta

| Caminho | Conteúdo |
|---|---|
| `<CNPJ>/<AAAA-MM>/<chave>.xml` | o XML de cada nota, pelo mês de emissão |
| `<CNPJ>/eventos/` | os eventos, como o cancelamento; a nota cancelada fica marcada na base e no CSV |
| `<CNPJ>/pendentes/` | o item que não deu para ler, guardado e reprocessado na rodada seguinte |
| `base.sqlite` | notas, eventos, pendências e o ponto onde cada empresa parou |
| `notas.csv` | uma linha por nota, em UTF-8 com BOM, separador `;` e decimal com vírgula; texto que começaria uma fórmula sai com apóstrofo na frente |
| `capturador.log` | uma linha por empresa e rodada, só com contagens |

Códigos de saída: `0` tudo certo; `1` uma empresa falhou ou apareceu pendência nova; `2` configuração ou uso
inválido; `3` outra rodada já está usando a pasta; `4` o guarda em tempo de execução barrou uma ação fora do
previsto (rede fora do ADN, criação de processo ou carga de código nativo) e nada foi gravado.

## Privacidade

- O programa só fala com o Ambiente de Dados Nacional (`adn.nfse.gov.br`), por HTTPS, usando o seu certificado.
  Nada vai para o Finance AI Lab nem para nenhuma IA.
- A senha fica no cofre do sistema. A chave privada só vai a disco cifrada, por instantes, e é apagada logo depois.
- A tela e o log mostram só contagens e o CNPJ mascarado (`**********0181`), nunca o texto de uma nota.
- As notas ficam na pasta que você escolheu. Proteja essa pasta como protege o resto do financeiro da empresa.

## Limites

- Só NFS-e do padrão nacional e só certificado A1 e-CNPJ. NF-e de produto (SEFAZ), CT-e, e-CPF, procurador e
  certificado A3 (token) ficam para depois.
- Município que não manda a nota para o ADN não aparece aqui.
- O ADN limita o ritmo das consultas. Uma empresa com muito histórico pode precisar de mais de uma rodada na
  primeira vez; o capturador continua de onde parou.
- Evento num formato que o capturador ainda não conhece fica em `pendentes/`, sem perda, até uma versão que o leia.

## Aviso

Rascunho operacional: a decisão e a revisão são do profissional responsável. O capturador baixa e organiza as notas;
a conferência fiscal e contábil continua sendo sua ou do profissional contábil responsável pela empresa.

## Reportar um problema ou pedir uma melhoria

Abra uma [issue](https://github.com/financeailab/capturador-de-notas/issues/new/choose). **Não anexe XML de nota, a
base, o CSV, o certificado nem a senha.** A saída do terminal pode ser colada: ela só traz contagens e o CNPJ
mascarado.

## Para quem desenvolve

Os testes usam só dado sintético: `pip install pytest` e `python -m pytest -q` na raiz. A pasta `ferramentas/` traz os
dois cheques que o CI roda em todo commit: o que confirma que só o `engine/adn.py` usa rede e o que confirma que a
saída nunca traz texto de nota.

## Licença

[Apache-2.0](LICENSE). Veja o [`NOTICE`](NOTICE).

## Autor

Douglas Ferreira ([LinkedIn](https://www.linkedin.com/in/douglasaf98)), Finance AI Lab
([financeailab.com.br](https://financeailab.com.br)).
