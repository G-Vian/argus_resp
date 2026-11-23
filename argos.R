# =============================================================================
#
#        A  R  G  O  S        acompanhamento semanal das fichas de meningite
#                             CVE / SES-SP
#
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡄
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠈
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⡀
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⢰⠇⠀⠀⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⢸⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠁⠀⠀⠀⠀⡇⢸⢸⡇⠇⢀
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠇⢀⡇⢸⣸⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⢀⠀⠃⢸⢠⢸⣿⢸⠀⠀⠀⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠐
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠰⠀⠀⠀⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⢸⢸⢠⠀⣾⢸⢸⣿⢸⢀⢠⠀⡆⡇⠀⠀⠐
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⢃⠀⢀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠁⠘⢸⢸⠀⡏⣿⢸⣿⢸⡘⢸⡀⡇⡇⡀⠀⠀⠀⠄⠀⠀⠀⠃
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⢄⠀⠀⢀⠀⠀⢢⡀⠀⠀⠀⢰⠀⣸⢸⢴⣇⡟⣾⣿⢸⣿⢸⡇⡇⡇⡇⠰⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠁
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠐⢄⠘⢄⠀⠣⡀⠀⠑⢄⠀⠱⣄⠁⡄⠆⣇⢿⢸⣾⣿⣇⣿⣿⣼⣿⣸⢷⡇⣼⢀⠀⠀⣠⠊⠀⣠⠆⠀⠀⠀⠁⠡⠎⠀⠈
#   ⠀⠀⠀⠀⠀⠀⠀⠈⠢⠀⠀⠀⡑⢄⠀⠁⠀⠑⢄⠙⢦⡀⠢⠙⡦⣈⢧⡻⣜⠼⣜⢯⣿⣿⣿⣿⣿⣿⣿⣿⣼⣹⢣⢣⢡⠞⣁⣴⠞⡁⠀⠀⠀⡠⠀⠀⠤⠀⠀⠀⠀⠀⡠
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠑⠠⡈⠒⠥⣀⠀⠐⠄⡉⠢⣝⡲⢬⡪⣎⢧⠽⠟⡺⠿⠛⠋⠉⠉⠉⠉⠉⠙⠛⠛⠿⣟⡻⢷⣾⣫⠥⡺⠕⣀⠤⡊⠀⢠⠀⢀⡠⠂⢀⡠⠊
#   ⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠒⠤⣀⠑⠢⠬⣽⣒⠤⠈⠒⡦⢭⣟⠚⣩⠰⠊⠁⠀⠀⠀⢀⡀⡀⠀⠀⠀⠀⠀⠀⢀⠀⠉⠓⢮⣝⡳⢻⣭⠖⣋⠠⣀⡴⠞⡩⠄⠚⠁⠀⠀⠄
#   ⠀⠀⠀⠀⠈⠀⠀⢀⡀⠈⠀⠀⠀⠈⠁⠒⠀⠬⠍⠛⠛⣚⣩⡆⠋⠁⣀⣴⣶⠏⣠⡞⣡⣶⣶⣶⡄⠀⠀⠀⠀⠀⠻⣷⣦⣀⠈⠛⢶⣬⣓⣒⢛⣃⣉⠠⠔⠀⠠⠂⠁⠀⠀⠀⠠
#   ⠀⠀⠀⠀⠂⠠⠀⠀⠀⠈⠁⠐⠢⠤⣁⣒⣒⣛⣂⣶⡟⠟⠉⢀⣤⣾⣿⣿⡏⢠⢶⡃⢿⣿⣿⠿⠁⠀⠀⠀⠀⠀⠀⢹⣿⣿⣷⣤⠀⠈⠻⢯⣟⣂⣂⣒⣒⣒⣈⡩⠥⠐⠈⠁⠀⠀⠠⠀⠈⠉⠁
#   ⠀⠀⢀⠀⠀⠀⠀⠈⠉⠉⠉⠀⠐⠒⣒⣛⣿⣿⣛⠉⠀⠀⠠⣾⣿⣿⣿⣿⡅⢊⠎⣹⠀⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣷⠀⠀⠀⠉⣛⠒⢲⠆⠡⠤⠤⠤⠒⠒⠀⠈⠀⠀⠀⠀⠀⢀⡀
#   ⢀⡀⠀⠀⠈⠀⡀⠠⠤⠐⠒⠒⣒⠒⠚⠳⠼⠛⠿⣶⣥⡠⡀⠙⢿⣿⣿⣿⣇⠀⠘⠄⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣮⣿⣿⣿⠟⠃⠀⢀⣴⣶⠿⠛⢿⣽⣛⠋⣉⣉⠉⠒⠒⠒⠂⠐⠀⠉
#   ⠀⠀⠀⠀⠀⠠⠀⠀⠒⠀⠩⠉⠀⠉⠉⢑⡚⢛⢋⠸⠝⠿⣮⣔⠄⡈⠛⠿⣿⣄⠈⠀⠁⠂⠄⠀⠀⠀⠀⠀⠀⢀⣼⣿⠿⠛⢁⢀⣠⣾⡻⠯⠭⣉⡙⠓⠚⠥⢄⡀⠀⠀⠈⠉⠐⠒
#   ⠀⠀⠀⠀⢀⠀⠀⠤⠄⠀⠤⠐⠀⠈⢉⡠⠄⣀⠤⠒⣈⡭⠾⢙⡿⣾⣤⣂⠀⣉⠑⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠊⣉⠠⣀⣬⡶⢿⣟⠯⢍⡛⠶⡤⠉⠑⠢⢄⠀⠀⠉⠀⠂⠠
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠒⡡⠔⠈⠀⠢⠋⠁⠂⠀⣡⠴⢃⣵⢟⡟⣷⣾⣿⣶⣶⣤⣤⣤⣴⣶⣦⣬⡷⣶⢿⢯⡳⣌⠢⢍⠛⠦⠌⠑⠠⠀⠀⠲⠤⡉⠢⠀⠈⠀⡀
#   ⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠀⠀⠀⠊⠀⠀⠀⠀⠄⠀⠀⠁⠘⢁⢀⠔⠁⠁⣽⢣⣇⡏⡏⣿⡟⣿⣿⢿⣿⣿⢸⡵⢹⣯⠆⠑⢜⢣⡀⠉⠢⣈⠂⠀⠀⠀⠀⠀⠀⠂⡀⠀⠀⠀⠑⢄
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠔⠀⠀⡠⠈⠀⠀⠀⣰⠑⢸⣹⢹⢿⣿⡇⣿⣿⢸⡟⢸⠈⣷⠁⠙⢇⠀⠀⠀⠙⢦⡀⠈⠃⢄⠀⠀⠀⠐⠀⠀⠀⠀⠀⠄
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⡀⠁⠀⠀⠀⠀⠀⠀⠀⠁⠃⠇⢸⢸⢸⠸⡏⡇⢸⣿⢸⣧⢨⠀⡝⡏⠀⠈⠂⠀⠀⠀⢀⠀⠀⠀⡀⠑⡀⠀⠀⠀⠈
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠒⠀⠀⠀⠀⠀⠀⡸⢸⢸⠀⣧⢿⢸⣿⠀⣿⠈⠀⠇⡇⠀⠀⠀⠐⠀⠀⠀⠀⠀⠀⠀⠀⠈⠄⠀⠀⠀⠄
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⢀⠀⢁⠘⠀⡀⠸⡌⢸⣿⠀⡏⠀⢀⠀⡄⠀⣤⠀⠀⠀⠐⠀⠀⠀⠀⠀⢠
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⡀⠇⠸⠃⢸⣿⠀⠇⠀⠀⢰⠀⠀⠀⠀⠀⠀⠀⠈⠀⠂
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⢀⠀⠀⠀⠁⠀⠂⠸⡟⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠂⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠤
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠈⠁
#   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰
#
#   "Centum luminibus cinctum caput Argus habebat;
#    inde suis vicibus capiebant bina quietem,
#    cetera servabant atque in statione manebant."
#
#   "Argos tinha a cabeça cercada de cem olhos; deles, dois de cada vez
#    descansavam, enquanto os outros vigiavam e permaneciam em seu posto."
#
#        Ovídio, Metamorfoses, Livro I, versos 625-627 (c. 8 d.C.).
#        Tradução livre.
#
#   Argos Panoptes, "o que tudo vê", era o gigante de cem olhos que Hera pôs
#   de guarda sobre Io. Hermes (Mercúrio) o fez adormecer tocando a flauta e
#   o matou; Hera guardou os cem olhos na cauda do pavão (mesmo livro).
#   O quadro que abre o Argos.bat é "Mercúrio embalando Argos para que durma",
#   de Ubaldo Gandolfi (c. 1770-1775), em domínio público.
#   Arte do olho (em braille Unicode): emojicombos.com/eye-ascii-art
#
# -----------------------------------------------------------------------------
#  O QUE O ARGOS FAZ
#   Lê a exportação mais recente do Sinan (bd_meningite_AAAA_MM_DD.RData, a
#   mesma da auditoria do meningococo) e atualiza UMA planilha Excel, sempre a
#   mesma (Argos_acompanhamento_meningites.xlsx):
#
#   Aba "Acompanhamento": todas as fichas que têm, ou já tiveram, alguma
#     pendência, da semana mais recente para a mais antiga, com uma faixa
#     colorida separando cada semana. Na mesma linha de cada ficha:
#       - a situação no Argos (NOVA, SEM MUDANÇA, MELHOROU, PIOROU, RESOLVIDA...)
#       - o que falta, a categoria (inconsistente, recuperável, não
#         identificado, campo em branco...) e a ação sugerida
#       - as colunas da equipe (Contato, Responsável, Data do contato,
#         Observações), que o Argos nunca apaga
#       - o caso no Sinan (classificação, evolução, exames, etiologia...)
#       - o histórico das últimas rodadas e o que mudou em cada uma
#       - as demais colunas da ficha (grupo que pode ser recolhido)
#   Abas "Resumo" e "Como ler".
#
#   O QUE O ARGOS PRESERVA a cada atualização:
#     - tudo o que for escrito nas colunas da equipe (amarelas);
#     - colunas novas que a equipe criar na aba Acompanhamento;
#     - linhas acrescentadas à mão (vão para o fim da aba);
#     - abas novas que a equipe criar.
#   Ele liga cada anotação à ficha pela coluna oculta "chave" (nº do Sinan +
#   data de notificação), então ordenar ou filtrar a planilha não atrapalha.
#   As demais colunas são refeitas a partir do Sinan a cada rodada.
#   Antes de gravar, guarda a versão anterior em backup/ (um arquivo só).
#
#   Junto da planilha fica o argos_historico.rds: é a memória do Argos (o
#   estado das fichas a cada rodada). Não apague. Na primeira rodada, ou se
#   alguma semana ficou sem rodar, ele reconstrói as semanas que faltam a
#   partir das exportações antigas do Sinan.
#
#   ATENÇÃO: a planilha e o histórico têm DADOS NOMINAIS (nome do paciente).
#   Trate conforme as normas de sigilo do serviço.
#
#  Ideias e regras do meningococo: auditoria_meningococo.R (v9).
#  Autor: Gabriel Vian, apoio técnico CVE/SES-SP
#  VERSÃO 1.0 (18/11/2026): primeira versão. Planilha única; situação, pendência
#    e histórico na mesma linha da ficha; etiologia, sorogrupo e critério entre
#    as primeiras colunas; checagens para fichas abertas, confirmadas e
#    descartadas; demais colunas da ficha; edições da equipe preservadas.
#  VERSÃO 1.0.1 (19/11/2026): pacotes que faltam são instalados na biblioteca do
#    usuário (a pasta do R em Arquivos de Programas não aceita gravação).
#  VERSÃO 1.0.2 (19/11/2026): o olho não é mais desenhado no prompt (o console do
#    Windows não mostra braille); a arte fica só aqui no cabeçalho.
#  VERSÃO 1.0.3 (19/11/2026): tudo o que o Argos grava (planilha, histórico,
#    backup) fica só na pasta argos do X:. Sem a pasta, ele para e não grava
#    em nenhum outro lugar (não há mais pasta reserva no computador).
#  VERSÃO 1.0.4 (19/11/2026): o olho volta ao prompt. Em braille no RStudio e no
#    Terminal do Windows; no prompt comum (cuja fonte não tem braille e mostra
#    "????"), o mesmo olho desenhado com pontos, traços e #.
#  VERSÃO 1.0.5 (19/11/2026): volta o olho em braille de antes (sai o de pontos).
#    O Argos.bat troca a fonte da janela pela Cascadia Mono, que tem braille (a
#    do Windows 11 ou, no Windows 10, o arquivo CascadiaMono-Regular.ttf da
#    pasta argos do X:), ou abre no Terminal do Windows; se nada der, o olho
#    não aparece, em vez dos "????". Somem os avisos "pacote ... foi compilado
#    no R versão ..." (inofensivos).
# =============================================================================

## ---- 1. ESCOLHAS (edite aqui) -------------------------------------------------
# exportações do Sinan (bd_meningite_AAAA_MM_DD.RData)
DIR_SNAPSHOT  <- "X:/CCD/CVE/RESPIRATORIAS/02_MENINGITE/4_base_acompanhamentos/acompanhamentos"
# pasta do Argos (compartilhada, para a equipe toda): planilha, histórico e backup
# ficam todos aqui, e o Argos não grava em nenhum outro lugar
PASTA_SAIDA   <- "X:/CCD/CVE/RESPIRATORIAS/02_MENINGITE/4_base_acompanhamentos/argos"
NOME_PLANILHA <- "Argos_acompanhamento_meningites.xlsx"

ARQ_SNAPSHOT  <- NA          # NA = exportação mais recente; ou o caminho de um .RData
ANOS          <- 2           # anos epidemiológicos na planilha: 1 = só o atual;
# 2 = atual e anterior; NA = todos os anos (fica pesada)
SEMANA_POR    <- "sintomas"  # semana de "sintomas" (início) ou de "notificacao"
PRAZO_ENCERRAMENTO <- 60     # dias para encerrar a investigação
SEMANAS_HISTORICO  <- 8      # rodadas mostradas no histórico de cada ficha
PENDENCIA_EVOLUCAO        <- TRUE  # confirmado com evolução em branco/ignorada
PENDENCIA_SEM_SOROGRUPO   <- TRUE  # meningococo sem sorogrupo por método que não sorogrupa
PENDENCIA_CRITERIO_EXAME  <- TRUE  # critério laboratorial sem o resultado do exame registrado
PENDENCIA_VIRAL_SEM_AGENTE <- FALSE # asséptica sem vírus identificado (são muitas: deixa a lista enorme)
ABRIR_EXCEL   <- TRUE        # abre a planilha no fim (quando roda pelo Argos.bat)
OLHO          <- "auto"      # olho de abertura em braille: "auto" (só quando a janela consegue
# mostrar braille), "braille" (sempre) ou "nenhum"
PREVIA        <- FALSE       # TRUE = planilha marcada como prévia (dados fictícios)

## ---- 2. PACOTES -----------------------------------------------------------------
.pac <- c("dplyr", "lubridate", "stringi", "openxlsx")
.tem <- function(p) vapply(p, function(x) nzchar(system.file(package = x)), logical(1))
.falta <- .pac[!.tem(.pac)]
if (length(.falta)) {
  # a pasta do R em "Arquivos de Programas" não aceita gravação: instala na biblioteca do usuário
  .lib <- path.expand(Sys.getenv("R_LIBS_USER"))
  if (!nzchar(.lib)) .lib <- file.path(Sys.getenv("LOCALAPPDATA"), "R", "win-library",
                                       paste(R.version$major, sub("\\..*$", "", R.version$minor), sep = "."))
  dir.create(.lib, recursive = TRUE, showWarnings = FALSE)
  .libPaths(c(.lib, .libPaths()))
  cat(">> Instalando os pacotes que faltam neste R (", R.version$version.string, "): ",
      paste(.falta, collapse = ", "), "\n   em ", .lib, "\n", sep = "")
  try(utils::install.packages(.falta, lib = .lib, repos = "https://cloud.r-project.org", quiet = TRUE), silent = TRUE)
  .falta <- .pac[!.tem(.pac)]
  if (length(.falta))
    stop("Faltam os pacotes ", paste(.falta, collapse = ", "), " no ", R.version$version.string,
         " e não foi possível instalá-los (sem internet ou sem permissão).\n",
         "  Saídas: (1) rode o argos.R pelo RStudio, que usa o R onde os pacotes já estão; ou\n",
         "  (2) no Argos.bat, preencha ARGOS_RSCRIPT com o Rscript.exe da versão do RStudio; ou\n",
         "  (3) instale os pacotes nesta versão do R: install.packages(c(\"",
         paste(.falta, collapse = "\", \""), "\"))", call. = FALSE)
}
# suppressWarnings: cala o aviso inofensivo "pacote ... foi compilado no R versão ..."
suppressWarnings(suppressPackageStartupMessages({ library(dplyr); library(lubridate); library(openxlsx) }))
# mesmo contorno do fig_bol_men.R para o falso erro "argument named `by`" do dplyr
if (exists("check_by_typo", envir = asNamespace("dplyr"), inherits = FALSE))
  utils::assignInNamespace("check_by_typo", function(...) invisible(NULL), ns = "dplyr")

OLHO_BRAILLE <- c(
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⢰⠇⠀⠀⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⢸⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠁⠀⠀⠀⠀⡇⢸⢸⡇⠇⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠇⢀⡇⢸⣸⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⢀⠀⠃⢸⢠⢸⣿⢸⠀⠀⠀⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠰⠀⠀⠀⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⢸⢸⢠⠀⣾⢸⢸⣿⢸⢀⢠⠀⡆⡇⠀⠀⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⢃⠀⢀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠁⠘⢸⢸⠀⡏⣿⢸⣿⢸⡘⢸⡀⡇⡇⡀⠀⠀⠀⠄⠀⠀⠀⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⢄⠀⠀⢀⠀⠀⢢⡀⠀⠀⠀⢰⠀⣸⢸⢴⣇⡟⣾⣿⢸⣿⢸⡇⡇⡇⡇⠰⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠐⢄⠘⢄⠀⠣⡀⠀⠑⢄⠀⠱⣄⠁⡄⠆⣇⢿⢸⣾⣿⣇⣿⣿⣼⣿⣸⢷⡇⣼⢀⠀⠀⣠⠊⠀⣠⠆⠀⠀⠀⠁⠡⠎⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠈⠢⠀⠀⠀⡑⢄⠀⠁⠀⠑⢄⠙⢦⡀⠢⠙⡦⣈⢧⡻⣜⠼⣜⢯⣿⣿⣿⣿⣿⣿⣿⣿⣼⣹⢣⢣⢡⠞⣁⣴⠞⡁⠀⠀⠀⡠⠀⠀⠤⠀⠀⠀⠀⠀⡠⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠑⠠⡈⠒⠥⣀⠀⠐⠄⡉⠢⣝⡲⢬⡪⣎⢧⠽⠟⡺⠿⠛⠋⠉⠉⠉⠉⠉⠙⠛⠛⠿⣟⡻⢷⣾⣫⠥⡺⠕⣀⠤⡊⠀⢠⠀⢀⡠⠂⢀⡠⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠒⠤⣀⠑⠢⠬⣽⣒⠤⠈⠒⡦⢭⣟⠚⣩⠰⠊⠁⠀⠀⠀⢀⡀⡀⠀⠀⠀⠀⠀⠀⢀⠀⠉⠓⢮⣝⡳⢻⣭⠖⣋⠠⣀⡴⠞⡩⠄⠚⠁⠀⠀⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠈⠀⠀⢀⡀⠈⠀⠀⠀⠈⠁⠒⠀⠬⠍⠛⠛⣚⣩⡆⠋⠁⣀⣴⣶⠏⣠⡞⣡⣶⣶⣶⡄⠀⠀⠀⠀⠀⠻⣷⣦⣀⠈⠛⢶⣬⣓⣒⢛⣃⣉⠠⠔⠀⠠⠂⠁⠀⠀⠀⠠⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠂⠠⠀⠀⠀⠈⠁⠐⠢⠤⣁⣒⣒⣛⣂⣶⡟⠟⠉⢀⣤⣾⣿⣿⡏⢠⢶⡃⢿⣿⣿⠿⠁⠀⠀⠀⠀⠀⠀⢹⣿⣿⣷⣤⠀⠈⠻⢯⣟⣂⣂⣒⣒⣒⣈⡩⠥⠐⠈⠁⠀⠀⠠⠀⠈⠉⠁⠀",
  "⠀⠀⢀⠀⠀⠀⠀⠈⠉⠉⠉⠀⠐⠒⣒⣛⣿⣿⣛⠉⠀⠀⠠⣾⣿⣿⣿⣿⡅⢊⠎⣹⠀⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣷⠀⠀⠀⠉⣛⠒⢲⠆⠡⠤⠤⠤⠒⠒⠀⠈⠀⠀⠀⠀⠀⢀⡀",
  "⢀⡀⠀⠀⠈⠀⡀⠠⠤⠐⠒⠒⣒⠒⠚⠳⠼⠛⠿⣶⣥⡠⡀⠙⢿⣿⣿⣿⣇⠀⠘⠄⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣮⣿⣿⣿⠟⠃⠀⢀⣴⣶⠿⠛⢿⣽⣛⠋⣉⣉⠉⠒⠒⠒⠂⠐⠀⠉⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠠⠀⠀⠒⠀⠩⠉⠀⠉⠉⢑⡚⢛⢋⠸⠝⠿⣮⣔⠄⡈⠛⠿⣿⣄⠈⠀⠁⠂⠄⠀⠀⠀⠀⠀⠀⢀⣼⣿⠿⠛⢁⢀⣠⣾⡻⠯⠭⣉⡙⠓⠚⠥⢄⡀⠀⠀⠈⠉⠐⠒⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⢀⠀⠀⠤⠄⠀⠤⠐⠀⠈⢉⡠⠄⣀⠤⠒⣈⡭⠾⢙⡿⣾⣤⣂⠀⣉⠑⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠊⣉⠠⣀⣬⡶⢿⣟⠯⢍⡛⠶⡤⠉⠑⠢⢄⠀⠀⠉⠀⠂⠠⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠒⡡⠔⠈⠀⠢⠋⠁⠂⠀⣡⠴⢃⣵⢟⡟⣷⣾⣿⣶⣶⣤⣤⣤⣴⣶⣦⣬⡷⣶⢿⢯⡳⣌⠢⢍⠛⠦⠌⠑⠠⠀⠀⠲⠤⡉⠢⠀⠈⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠀⠀⠀⠊⠀⠀⠀⠀⠄⠀⠀⠁⠘⢁⢀⠔⠁⠁⣽⢣⣇⡏⡏⣿⡟⣿⣿⢿⣿⣿⢸⡵⢹⣯⠆⠑⢜⢣⡀⠉⠢⣈⠂⠀⠀⠀⠀⠀⠀⠂⡀⠀⠀⠀⠑⢄⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠔⠀⠀⡠⠈⠀⠀⠀⣰⠑⢸⣹⢹⢿⣿⡇⣿⣿⢸⡟⢸⠈⣷⠁⠙⢇⠀⠀⠀⠙⢦⡀⠈⠃⢄⠀⠀⠀⠐⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⡀⠁⠀⠀⠀⠀⠀⠀⠀⠁⠃⠇⢸⢸⢸⠸⡏⡇⢸⣿⢸⣧⢨⠀⡝⡏⠀⠈⠂⠀⠀⠀⢀⠀⠀⠀⡀⠑⡀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠒⠀⠀⠀⠀⠀⠀⡸⢸⢸⠀⣧⢿⢸⣿⠀⣿⠈⠀⠇⡇⠀⠀⠀⠐⠀⠀⠀⠀⠀⠀⠀⠀⠈⠄⠀⠀⠀⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⢀⠀⢁⠘⠀⡀⠸⡌⢸⣿⠀⡏⠀⢀⠀⡄⠀⣤⠀⠀⠀⠐⠀⠀⠀⠀⠀⢠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⡀⠇⠸⠃⢸⣿⠀⠇⠀⠀⢰⠀⠀⠀⠀⠀⠀⠀⠈⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⢀⠀⠀⠀⠁⠀⠂⠸⡟⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠂⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
  "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"
)
.diga <- function(...) cat(..., "\n", sep = "")
.abertura <- function() {
  tipo <- OLHO
  if (identical(tipo, "auto")) {
    # pelo Argos.bat: ele avisa (ARGOS_BRAILLE) se conseguiu uma fonte com braille;
    # fora dele: RStudio e Terminal do Windows mostram braille, o prompt comum não
    braille_ok <- if (Sys.getenv("ARGOS_BAT") == "1") Sys.getenv("ARGOS_BRAILLE") == "1" else
      .Platform$OS.type != "windows" || nzchar(Sys.getenv("RSTUDIO")) || nzchar(Sys.getenv("WT_SESSION"))
    tipo <- if (braille_ok) "braille" else "nenhum"
  }
  arte <- if (identical(tipo, "braille")) OLHO_BRAILLE else character(0)
  .diga("")
  if (length(arte)) { for (l in arte) .diga("   ", l); .diga("") }
  .diga("   A R G O S   ·   acompanhamento semanal das fichas de meningite (CVE/SES-SP)")
  .diga("   \"cetera servabant atque in statione manebant\"  (Ovídio, Met. I, 627)")
  .diga("   os outros [olhos] vigiavam e permaneciam em seu posto")
  .diga(strrep("-", 84))
}
.abertura()

## ---- 3. FUNÇÕES DE APOIO E TABELAS -----------------------------------------------
.txt <- function(x) {
  v <- as.character(x)
  mau <- !is.na(v) & !validUTF8(v)
  if (any(mau)) v[mau] <- iconv(v[mau], from = "latin1", to = "UTF-8", sub = "")
  v <- trimws(v); v[v %in% c("", "NA")] <- NA
  v
}
# código do Sinan sem zeros à esquerda; "0", "00" = sem informação (como na auditoria v7)
.cod <- function(x) { v <- sub("^0+", "", .txt(x)); v[!is.na(v) & v == ""] <- NA; v }
.data <- function(x) {
  if (inherits(x, "Date")) return(x)
  if (inherits(x, "POSIXt")) return(as.Date(x))
  x <- .txt(x)
  out <- suppressWarnings(as.Date(x, format = "%Y-%m-%d"))
  i <- is.na(out) & grepl("^\\d{8}$", x);               out[i] <- as.Date(x[i], "%Y%m%d")
  i <- is.na(out) & grepl("^\\d{2}/\\d{2}/\\d{4}$", x); out[i] <- as.Date(x[i], "%d/%m/%Y")
  i <- is.na(out) & grepl("^\\d{2}/\\d{2}/\\d{2}$", x); out[i] <- as.Date(x[i], "%d/%m/%y")
  out
}
.semana <- function(d) lubridate::floor_date(d, "week", week_start = 7)
.n0  <- function(v) formatC(v, format = "d", big.mark = ".", decimal.mark = ",")
.dm  <- function(d) format(d, "%d/%m")
.titulo <- function(x) {                       # "SAO JOSE DO RIO PRETO" -> "Sao Jose do Rio Preto"
  x <- tools::toTitleCase(tolower(x))
  gsub("\\b(Da|De|Do|Das|Dos|E)\\b", "\\L\\1", x, perl = TRUE)
}
.acentos <- function(v) {                      # rótulos do script da base vêm sem acento
  v <- sub("^Nao$", "Não", v); v <- sub("^Nao ", "Não ", v); v <- sub("^Obito", "Óbito", v)
  v <- sub("^Domicilio$", "Domicílio", v); v <- sub("^Vizinhanca$", "Vizinhança", v)
  sub("^Outro estado/municipio$", "Outro estado/município", v)
}
.na_janela <- function(dref, ano_ref)
  !is.na(dref) & (is.na(ANOS) | lubridate::epiyear(dref) >= ano_ref - ANOS + 1)

# ---- categorias de pendência (ordem = desempate entre pendências da mesma prioridade)
CATS <- data.frame(stringsAsFactors = FALSE,
                   cat   = c("INCONSISTENTE", "RECUPERÁVEL", "ENCERRAMENTO ATRASADO", "NÃO IDENTIFICADO",
                             "DUPLICIDADE", "CAMPO EM BRANCO", "SEM SOROGRUPO", "EM INVESTIGAÇÃO"),
                   curto = c("INCONSISTENTE", "RECUPERÁVEL", "ATRASADA", "NÃO IDENTIF.",
                             "DUPLICIDADE", "EM BRANCO", "SEM SOROGR.", "EM INVESTIG."),
                   segue = c("Segue inconsistente", "Segue sem corrigir (recuperável)", "Segue atrasada",
                             "Segue sem identificação", "Segue duplicada", "Segue com campo em branco",
                             "Segue sem sorogrupo", "Segue em investigação"),
                   fundo = c("#F4CCCC", "#FCE4D6", "#F8CBAD", "#FFF2CC", "#DDF2EF", "#EDEDED", "#E4DFEC", "#DDEBF7"),
                   letra = c("#9C0006", "#9C5700", "#843C0C", "#7F6000", "#0B5345", "#404040", "#5B3A87", "#1F4E79"),
                   prioridade = c("Alta ou média", "Média ou alta", "Alta", "Média (alta se óbito)", "Média",
                                  "Média ou baixa", "Baixa", "Baixa"),
                   significa = c(
                     "A ficha se contradiz: etiologia, sorogrupo, classificação, critério ou datas não batem com os exames ou entre si.",
                     "A informação que falta já existe (o exame identificou o agente/sorogrupo); basta registrar.",
                     paste0("Ficha em investigação há mais de ", PRAZO_ENCERRAMENTO, " dias (prazo de encerramento)."),
                     "Caso confirmado sem agente: etiologia não especificada ou em branco, ou outras bactérias/outra etiologia sem o agente.",
                     "Mais de um registro com o mesmo número e a mesma data de notificação.",
                     "Campo importante vazio: evolução, data do óbito, critério, quimioprofilaxia ou resultado do exame do critério.",
                     "Meningococo sem sorogrupo e sem exame que permitisse sorogrupar (nada a recuperar no Sinan).",
                     paste0("Ficha ainda aberta, dentro do prazo de ", PRAZO_ENCERRAMENTO, " dias.")))
OUTROS_ESTADOS <- data.frame(stringsAsFactors = FALSE,
                             cat   = c("OK", "DESCARTADO", "FORA DA BASE"),
                             curto = c("\u2713 EM DIA", "DESCARTADO", "FORA DA BASE"),
                             fundo = c("#E2EFDA", "#F2F2F2", "#FFFFFF"),
                             letra = c("#375623", "#7F7F7F", "#A6A6A6"))
PRIOR <- c("Alta" = 1, "Média" = 2, "Baixa" = 3)
# situação da ficha no Argos (comparada com a rodada anterior)
SITUACOES <- data.frame(stringsAsFactors = FALSE,
                        sit   = c("VOLTOU", "PIOROU", "NOVA", "SEM MUDANÇA", "MUDOU", "MELHOROU", "PENDENTE",
                                  "RESOLVIDA NESTA SEMANA", "RESOLVIDA", "SAIU DA BASE"),
                        fundo = c("#F4CCCC", "#F4CCCC", "#E4DFEC", "#FFF2CC", "#DDEBF7", "#EBF1DE", "#FFF2CC",
                                  "#C6EFCE", "#E2EFDA", "#F2F2F2"),
                        letra = c("#9C0006", "#9C0006", "#5B3A87", "#7F6000", "#1F4E79", "#4F6228", "#7F6000",
                                  "#006100", "#375623", "#7F7F7F"),
                        significa = c(
                          "Tinha sido resolvida e voltou a ter pendência.",
                          "A pendência ficou mais grave ou ganhou itens desde a semana anterior.",
                          "Entrou na lista nesta semana (notificação nova ou ficha alterada).",
                          "Segue com a mesma pendência da semana anterior.",
                          "A pendência trocou de tipo, com a mesma prioridade.",
                          "Ainda há pendência, mas menos grave ou com menos itens que na semana anterior.",
                          "Pendente (primeira semana do Argos, sem comparação).",
                          "A pendência sumiu nesta semana (ficha corrigida, encerrada ou descartada).",
                          "Resolvida numa semana anterior; fica na lista para registro.",
                          "A notificação não aparece mais na exportação do Sinan (excluída?)."))
.rot_estado <- function(s) ifelse(s %in% CATS$cat, CATS$curto[match(s, CATS$cat)],
                                  ifelse(s %in% OUTROS_ESTADOS$cat, OUTROS_ESTADOS$curto[match(s, OUTROS_ESTADOS$cat)], s))
.mud_estado <- function(a, b) {
  if (identical(a, b)) return(NA)
  if (b == "OK") return(paste0("pendência resolvida (era ", .rot_estado(a), ")"))
  if (b == "DESCARTADO") return("ficha descartada")
  if (a %in% c("OK", "DESCARTADO")) return(paste0("voltou à lista: ", .rot_estado(b)))
  paste0("pendência: ", .rot_estado(a), " \u2192 ", .rot_estado(b))
}

# ---- exames do Sinan
EXAMES <- data.frame(stringsAsFactors = FALSE,
                     col  = c("LAB_CTLIQU", "LAB_CTSANG", "LAB_CTLESA", "LAB_PCLIQU", "LAB_PCSANG", "LAB_PCLESA",
                              "LAB_AGLIQU", "LAB_AGSANG", "LAB_CILIQU", "LAB_CISANG",
                              "LAB_BCLIQU", "LAB_BCSANG", "LAB_BCLESA", "LAB_ISLIQU"),
                     rot  = c("Cultura LCR", "Cultura sangue", "Cultura lesão", "PCR LCR", "PCR sangue", "PCR lesão",
                              "Látex LCR", "Látex sangue", "CIE LCR", "CIE sangue",
                              "Bacterioscopia LCR", "Bacterioscopia sangue", "Bacterioscopia lesão", "Isol. viral LCR"),
                     tipo = c(rep("sorog", 10), rep("bc", 3), "is"),
                     crit = c(rep("1", 3), rep("9", 3), rep("3", 2), rep("2", 2), rep("5", 3), "8"))
RES_AGENTE <- c("1" = "N. meningitidis", "6" = "H. influenzae", "7" = "S. pneumoniae",
                "28" = "outra bactéria", "51" = "negativo",
                "37" = "caxumba", "38" = "sarampo", "39" = "herpes simples", "40" = "varicela",
                "41" = "rubéola", "42" = "outros fungos", "43" = "Cryptococcus", "48" = "Toxoplasma",
                "52" = "outros parasitas", "55" = "influenza", "56" = "echovírus", "59" = "enterovírus",
                "63" = "coxsackie", "70" = "adenovírus", "71" = "vírus do Nilo Ocidental",
                "72" = "dengue", "73" = "arbovírus", "74" = "outros vírus", "75" = "não identificado")
RES_BC <- c("3" = "diplococos Gram-negativos", "8" = "diplococos Gram-positivos", "28" = "outras bactérias",
            "29" = "bastonetes Gram-positivos", "30" = "bastonetes Gram-negativos",
            "31" = "bacilos Gram-positivos", "32" = "bacilos Gram-negativos", "33" = "cocos Gram-positivos",
            "34" = "cocos Gram-negativos", "35" = "diplobacilos Gram-negativos", "36" = "cocobacilos",
            "51" = "negativo")
CRITERIOS <- c("1" = "Cultura", "2" = "CIE", "3" = "Látex", "4" = "Clínico", "5" = "Bacterioscopia",
               "6" = "Quimiocitológico", "7" = "Clínico-epidemiológico", "8" = "Isolamento viral",
               "9" = "PCR", "10" = "Outras técnicas")
SOROGRUPOS <- c("1" = "A", "2" = "B", "3" = "C", "4" = "D", "5" = "X", "6" = "Y", "7" = "Z",
                "8" = "W", "9" = "29E")
FORMAS <- c("1" = "Meningococcemia", "2" = "Meningite meningocócica", "3" = "Meningite meningocócica com meningococcemia",
            "4" = "Meningite tuberculosa", "5" = "Meningite bacteriana não especificada",
            "6" = "Meningite não especificada", "7" = "Meningite asséptica", "8" = "Meningite de outra etiologia",
            "9" = "Meningite por hemófilo", "10" = "Meningite pneumocócica")
SIM_NAO <- c("1" = "Sim", "2" = "Não", "9" = "Ignorado")
COD_NAO_FEITO <- c("61", "62")

# ---- demais colunas da ficha (vão no fim da aba, em grupo que pode ser recolhido)
#      rótulo | colunas de origem (a 1ª que existir) | tipo
DEMAIS <- data.frame(stringsAsFactors = FALSE, matrix(ncol = 3, byrow = TRUE, c(
  "Data de nascimento", "DT_NASC", "data",
  "Faixa etária", "faixa_etaria2", "txt",
  "Data da investigação", "DT_INVEST", "data",
  "Data de digitação", "DT_DIGITA", "data",
  "Município de notificação (IBGE)", "ID_MUNICIP", "txt",
  "Unidade notificante (CNES)", "ID_UNIDADE", "txt",
  "Internação", "internacao|ATE_HOSPIT", "sn",
  "Data da internação", "ATE_INTERN", "data",
  "Município do hospital (IBGE)", "ATE_MUNICI", "txt",
  "Forma clínica (diagnóstico)", "CON_DIAGES", "forma",
  "Vírus", "virus", "txt",
  "Outra bactéria", "out_bac", "txt",
  "Outra etiologia", "outr_etio", "txt",
  "Punção lombar", "LAB_PUNCAO", "sn",
  "Data da punção", "LAB_DTPUNC", "data",
  "Cultura LCR", "LAB_CTLIQU", "exame", "Cultura sangue", "LAB_CTSANG", "exame",
  "Cultura lesão", "LAB_CTLESA", "exame", "PCR LCR", "LAB_PCLIQU", "exame",
  "PCR sangue", "LAB_PCSANG", "exame", "PCR lesão", "LAB_PCLESA", "exame",
  "Látex LCR", "LAB_AGLIQU", "exame", "Látex sangue", "LAB_AGSANG", "exame",
  "CIE LCR", "LAB_CILIQU", "exame", "CIE sangue", "LAB_CISANG", "exame",
  "Bacterioscopia LCR", "LAB_BCLIQU", "exame_bc", "Bacterioscopia sangue", "LAB_BCSANG", "exame_bc",
  "Bacterioscopia lesão", "LAB_BCLESA", "exame_bc", "Isolamento viral LCR", "LAB_ISLIQU", "exame",
  "Data da evolução", "MED_DT_EVO", "data",
  "Quimioprofilaxia", "quimioprofilaxia|MED_QUIMIO", "sn",
  "Data da quimioprofilaxia", "MED_DT_QUI", "data",
  "Caso secundário", "caso_secund|ANT_SECUND", "sn",
  "Contato com caso", "contato_caso", "txt",
  "Vacina conjugada C (vac_conjc)", "vac_conjc", "txt",
  "Vacina polissacarídica A/C (vac_poliac)", "vac_poliac", "txt",
  "Vacina polissacarídica B/C (vac_polibc)", "vac_polibc", "txt",
  "Vacina Hib/tetravalente (vac_tethib)", "vac_tethib", "txt",
  "Vacina pneumocócica (vac_pneum)", "vac_pneum", "txt",
  "BCG (vac_bcg)", "vac_bcg", "txt",
  "Vacina tríplice (vac_tri)", "vac_tri", "txt",
  "Outra vacina (outvac)", "outvac", "txt",
  "Cefaleia", "cefaleia|CLI_CEFALE", "sn", "Febre", "febre|CLI_FEBRE", "sn",
  "Vômito", "vomito|CLI_VOMITO", "sn", "Convulsões", "convulsoes|CLI_CONVUL", "sn",
  "Rigidez de nuca", "rigidez_nuca|CLI_RIGIDE", "sn", "Kernig/Brudzinski", "Kernig_brudzinski|CLI_KERNIG", "sn",
  "Fontanela abaulada", "abaula_fontanela|CLI_ABAULA", "sn", "Coma", "coma|CLI_COMA", "sn",
  "Petéquias/sufusões", "petequias|CLI_PETEQU", "sn",
  "Ano epidemiológico", "anoepi", "txt", "SE epidemiológica", "sepi", "txt")))
names(DEMAIS) <- c("rot", "orig", "tipo")
DEMAIS$id <- paste0("d", seq_len(nrow(DEMAIS)))
COLS_LIDAS <- unique(c("NU_NOTIFIC", "DT_NOTIFIC", "NM_PACIENT", "DT_SIN_PRI", "NU_IDADE_N", "idade",
                       "CS_SEXO", "MUNI_RESID", "GVE_RESID", "DRS_RESID", "CLASSI_FIN", "classi_fin",
                       "EVOLUCAO", "evolucao", "DT_ENCERRA", "DT_INVEST", "DT_DIGITA", "CON_DIAGES",
                       "CLA_SOROGR", "CRITERIO", "etiologia", "out_bac", "outr_etio", "virus",
                       "LAB_PUNCAO", "MED_DT_EVO", "DT_NASC", "MED_QUIMIO", "quimioprofilaxia", EXAMES$col,
                       "CLA_ME_BAC", "CLA_ME_ETI", "CLA_ME_ASS",
                       unlist(strsplit(DEMAIS$orig, "|", fixed = TRUE))))

## ---- 4. LEITURA DE UMA EXPORTAÇÃO DO SINAN -----------------------------------------
lista_snapshots <- function() {
  a <- list.files(DIR_SNAPSHOT, pattern = "^bd_meningite_.*\\.RData$", full.names = TRUE)
  if (!length(a)) return(data.frame(arq = character(), data = as.Date(character())))
  d <- as.Date(stringi::stri_extract_first_regex(basename(a), "\\d{4}_\\d{2}_\\d{2}"), "%Y_%m_%d")
  d[is.na(d)] <- as.Date(file.mtime(a[is.na(d)]))
  out <- data.frame(arq = a, data = d, stringsAsFactors = FALSE)
  out[order(out$data), ]
}
ler_snapshot <- function(arq) {
  e <- new.env()
  load(arq, envir = e)
  x <- if (exists("dbf", envir = e, inherits = FALSE)) e$dbf else get(ls(e)[1], envir = e)
  rm(e)
  x <- as.data.frame(x)[, intersect(COLS_LIDAS, names(x)), drop = FALSE]
  invisible(gc())
  x
}

## ---- 5. O OLHAR DO ARGOS: estado e pendências de cada ficha ------------------------
# devolve uma linha por notificação da janela (duplicatas reunidas), com as
# pendências, a categoria principal, os textos da planilha e as demais colunas
estado <- function(x, data_base, demais = TRUE) {
  g <- function(cc) if (cc %in% names(x)) x[[cc]] else rep(NA, nrow(x))
  cf <- .txt(g("classi_fin")); CF <- .cod(g("CLASSI_FIN"))
  classif <- dplyr::case_when(cf %in% "Confirmado" | (is.na(cf) & CF %in% "1") ~ "Confirmado",
                              cf %in% "Descartado" | (is.na(cf) & CF %in% "2") ~ "Descartado",
                              TRUE ~ "Em investigação")
  dt_not <- .data(g("DT_NOTIFIC")); dt_sin <- .data(g("DT_SIN_PRI"))
  dref <- if (SEMANA_POR == "notificacao") dplyr::coalesce(dt_not, dt_sin) else dplyr::coalesce(dt_sin, dt_not)
  jan <- .na_janela(dref, lubridate::epiyear(data_base))
  x <- x[jan, , drop = FALSE]; classif <- classif[jan]; dt_not <- dt_not[jan]; dt_sin <- dt_sin[jan]; dref <- dref[jan]
  n <- nrow(x)
  if (!n) return(NULL)
  
  nu <- gsub('"', "", .txt(g("NU_NOTIFIC")))
  chave <- ifelse(is.na(nu), paste0("sem_numero_", seq_len(n)), paste(nu, as.character(dt_not)))
  # duplicatas: fica o registro mais recente (DT_ENCERRA/DT_INVEST/DT_DIGITA), como na auditoria v9
  n_reg <- as.integer(table(chave)[chave])
  ref <- suppressWarnings(do.call(pmax, c(lapply(c("DT_ENCERRA", "DT_INVEST", "DT_DIGITA"), function(cc) .data(g(cc))),
                                          list(na.rm = TRUE))))
  ref[is.na(ref)] <- as.Date("1900-01-01")
  o <- order(chave, ref, classif == "Confirmado")
  fica <- seq_len(n) %in% o[!duplicated(chave[o], fromLast = TRUE)]
  x <- x[fica, , drop = FALSE]
  classif <- classif[fica]; dt_not <- dt_not[fica]; dt_sin <- dt_sin[fica]; dref <- dref[fica]
  nu <- nu[fica]; chave <- chave[fica]; n_reg <- n_reg[fica]
  n <- nrow(x)
  
  # ---- exames
  ex <- lapply(EXAMES$col, function(cc) .cod(g(cc))); names(ex) <- EXAMES$col
  feito <- lapply(ex, function(v) !is.na(v) & !(v %in% COD_NAO_FEITO))
  algum_exame <- Reduce(`|`, feito)
  sg <- EXAMES$col[EXAMES$tipo == "sorog"]; bc <- EXAMES$col[EXAMES$tipo == "bc"]
  or_ <- function(cols, f) Reduce(`|`, lapply(cols, function(cc) f(ex[[cc]], feito[[cc]])))
  sorog_feito    <- or_(sg, function(v, f) f)
  sorog_positivo <- or_(sg, function(v, f) f & v != "51")
  sorog_achou_nm <- or_(sg, function(v, f) f & v == "1")
  outro_exame    <- or_(c(bc, "LAB_ISLIQU"), function(v, f) f)
  lcr_feito      <- or_(EXAMES$col[grepl("LIQU$", EXAMES$col)], function(v, f) f)
  ag_cod <- c("1", "6", "7", "28")
  ag_lista <- lapply(seq_len(n), function(i) {      # agentes bacterianos de cultura/PCR/látex/CIE
    a <- unique(unlist(lapply(sg, function(cc) ex[[cc]][i]))); a[!is.na(a) & a %in% ag_cod]
  })
  agente <- vapply(ag_lista, function(a) if (length(a)) paste(RES_AGENTE[a[order(match(a, ag_cod))]], collapse = ", ") else "",
                   character(1))
  bc_res <- vapply(seq_len(n), function(i) {
    a <- unique(unlist(lapply(bc, function(cc) ex[[cc]][i])))
    a <- a[!is.na(a) & !(a %in% c(COD_NAO_FEITO, "51"))]
    if (length(a)) paste(ifelse(a %in% names(RES_BC), RES_BC[a], paste("cód.", a)), collapse = ", ") else ""
  }, character(1))
  rotulo_res <- function(v, tipo) {
    tab <- if (tipo == "bc") RES_BC else RES_AGENTE
    ifelse(v %in% names(tab), tab[v], paste("cód.", v))
  }
  partes <- mapply(function(cc, rot, tipo) ifelse(feito[[cc]], paste0(rot, ": ", rotulo_res(ex[[cc]], tipo)), NA),
                   EXAMES$col, EXAMES$rot, EXAMES$tipo, SIMPLIFY = FALSE)
  exames_txt <- apply(do.call(cbind, partes), 1, function(r) paste(r[!is.na(r)], collapse = " · "))
  pun <- .cod(g("LAB_PUNCAO"))
  exames_txt[exames_txt == ""] <- ifelse(pun[exames_txt == ""] %in% "2", "Punção não realizada; nenhum exame",
                                         "Nenhum exame registrado")
  
  # ---- critério, diagnóstico, etiologia e sorogrupo (como estão na ficha)
  crit_n <- .cod(g("CRITERIO"))
  criterio <- ifelse(crit_n %in% names(CRITERIOS), CRITERIOS[crit_n], ifelse(is.na(crit_n), NA, paste("cód.", crit_n)))
  criterio <- ifelse(is.na(criterio), ifelse(classif == "Confirmado", "(em branco)", "—"), criterio)
  crit_sorog <- crit_n %in% c("1", "2", "3", "9")
  crit_outro <- crit_n %in% c("4", "5", "6", "7", "8", "10")
  cd <- .cod(g("CON_DIAGES"))
  et <- .txt(g("etiologia"))
  if (all(is.na(et))) {                           # exportação sem a coluna derivada
    et <- dplyr::case_when(classif == "Em investigação" ~ "Em investigacao",
                           classif != "Confirmado" ~ "Sem informacao",
                           cd %in% c("1", "2", "3") ~ "Meningococo", cd %in% c("4", "5") ~ "Outra bacteria",
                           cd == "6" ~ "Nao especificada", cd == "7" ~ "Asseptica", cd == "8" ~ "Outra etiologia",
                           cd == "9" ~ "Hemofilo", cd == "10" ~ "Pneumococo", is.na(cd) ~ "Nao determinada",
                           TRUE ~ "Sem informacao")
  }
  sor_n <- .cod(g("CLA_SOROGR")); tem_sorog <- sor_n %in% names(SOROGRUPOS)
  # agente específico de "outras bactérias" (CLA_ME_BAC), "outra etiologia" (CLA_ME_ETI) e vírus (CLA_ME_ASS)
  bac_n <- .cod(g("CLA_ME_BAC")); eti_n <- .cod(g("CLA_ME_ETI")); ass_n <- .cod(g("CLA_ME_ASS"))
  ob <- .acentos(.txt(g("out_bac"))); oe <- .acentos(.txt(g("outr_etio"))); vi <- .acentos(.txt(g("virus")))
  esp <- function(v) !is.na(v) & !grepl("^N(a|ã)o (determinad|identificad)", v)
  tem_cod <- function(cc) cc %in% names(x) && any(!is.na(g(cc)))
  bac_esp <- if (tem_cod("CLA_ME_BAC")) !is.na(bac_n) & bac_n != "81" else esp(ob)
  eti_esp <- if (tem_cod("CLA_ME_ETI")) !is.na(eti_n) else esp(oe)
  vir_esp <- if (tem_cod("CLA_ME_ASS")) !is.na(ass_n) & ass_n != "75" else esp(vi)
  tb <- et == "Outra bacteria" & cd %in% "4"
  etiologia <- dplyr::case_when(
    classif == "Descartado"                ~ "—",
    classif == "Em investigação"           ~ "Em investigação",
    et == "Meningococo"                    ~ "Meningococo",
    et == "Pneumococo"                     ~ "Pneumococo",
    et == "Hemofilo"                       ~ "Haemophilus influenzae",
    tb                                     ~ "Tuberculosa",
    et == "Outra bacteria" & bac_esp       ~ paste0("Outras bactérias: ", ifelse(is.na(ob), paste("cód.", bac_n), ob)),
    et == "Outra bacteria"                 ~ paste0("Outras bactérias: ", ifelse(bac_n %in% "81", "não determinada", "agente em branco")),
    et == "Nao especificada"               ~ "Não especificada",
    et == "Nao determinada"                ~ "(em branco)",
    et == "Asseptica" & vir_esp            ~ paste0("Asséptica: ", ifelse(is.na(vi), paste("cód.", ass_n), vi)),
    et == "Asseptica"                      ~ paste0("Asséptica", ifelse(ass_n %in% "75", ": não identificado", "")),
    et == "Outra etiologia" & eti_esp      ~ paste0("Outra etiologia: ", ifelse(is.na(oe), paste("cód.", eti_n), oe)),
    et == "Outra etiologia"                ~ "Outra etiologia: agente em branco",
    TRUE                                   ~ "Sem informação")
  sorogrupo <- ifelse(tem_sorog, SOROGRUPOS[sor_n], ifelse(!is.na(sor_n), paste("cód.", sor_n),
                                                           ifelse(et == "Meningococo" & classif == "Confirmado", "(em branco)", "—")))
  # ---- evolução (do campo bruto, para separar "em branco" de "ignorado")
  ev <- .cod(g("EVOLUCAO"))
  evolucao <- if (all(is.na(ev)) && "evolucao" %in% names(x)) {
    v <- .txt(g("evolucao")); ifelse(is.na(v), "Em branco", .acentos(v))
  } else dplyr::case_when(ev == "1" ~ "Alta", ev == "2" ~ "Óbito por meningite",
                          ev == "3" ~ "Óbito por outra causa", ev == "9" ~ "Ignorado", TRUE ~ "Em branco")
  evolucao[classif == "Em investigação" & evolucao == "Em branco"] <- "—"
  obito <- grepl("^Óbito", evolucao)
  dt_enc <- .data(g("DT_ENCERRA")); dt_evo <- .data(g("MED_DT_EVO")); dt_nasc <- .data(g("DT_NASC"))
  quimio <- if ("MED_QUIMIO" %in% names(x)) .cod(g("MED_QUIMIO")) else
    dplyr::case_when(.txt(g("quimioprofilaxia")) == "Sim" ~ "1", .txt(g("quimioprofilaxia")) %in% c("Nao", "Não") ~ "2",
                     TRUE ~ NA_character_)
  tem_quimio <- "MED_QUIMIO" %in% names(x) || "quimioprofilaxia" %in% names(x)
  
  # ---- pendências: uma linha por (ficha, pendência), cada uma com um rótulo curto
  dias <- as.integer(data_base - dt_not)
  conf <- classif == "Confirmado"; inv <- classif == "Em investigação"; desc <- classif == "Descartado"
  P <- list()
  add <- function(i, cat, pri, rot) {
    i <- which(i & !is.na(i)); if (!length(i)) return(invisible())
    P[[length(P) + 1]] <<- data.frame(id = i, cat = cat, pri = rep_len(pri, n)[i], rot = rep_len(rot, n)[i],
                                      stringsAsFactors = FALSE)
  }
  .ob <- function(s) ifelse(obito, paste0(s, " (óbito)"), s)
  # fichas abertas
  atras <- inv & !is.na(dias) & dias > PRAZO_ENCERRAMENTO
  add(atras, "ENCERRAMENTO ATRASADO", "Alta", paste0("ATRASADA: aberta há ", dias, " dias (prazo: ", PRAZO_ENCERRAMENTO, " dias)"))
  add(inv & !atras, "EM INVESTIGAÇÃO", "Baixa",
      paste0("EM INVESTIGAÇÃO: há ", dias, ifelse(dias == 1, " dia", " dias")))
  add(inv & agente != "", "RECUPERÁVEL", "Média", paste0("RECUPERÁVEL: o exame já identificou ", agente))
  # meningococo: classes da auditoria (grupo I, forma clínica 1/2/3)
  men <- conf & et == "Meningococo"
  esp_ag <- lapply(ag_lista, function(a) a[a %in% c("1", "6", "7")])      # N. meningitidis, Hib, pneumococo
  tem_outro_ag <- vapply(esp_ag, function(a) length(a) > 0 && !("1" %in% a), logical(1))
  fez_sorog <- sorog_feito | crit_sorog
  c1b <- men & tem_sorog & !fez_sorog
  c1c <- men & tem_sorog & tem_outro_ag
  c2  <- men & !tem_sorog & (sorog_achou_nm | crit_sorog)
  c3  <- men & !tem_sorog & !c2 & sorog_feito & !sorog_positivo
  c3b <- men & !tem_sorog & !c2 & sorog_positivo
  c4  <- men & !tem_sorog & !c2 & !c3 & !c3b & (outro_exame | crit_outro)
  c5  <- men & !tem_sorog & !c2 & !c3 & !c3b & !c4
  add(c1b, "INCONSISTENTE", "Alta", "INCONSISTENTE: sorogrupo sem exame nem critério laboratorial que o sustente")
  add(c1c, "INCONSISTENTE", "Alta", paste0("INCONSISTENTE: sorogrupo ", SOROGRUPOS[sor_n], ", mas o exame identificou ", agente))
  add(c2, "RECUPERÁVEL", "Média", "RECUPERÁVEL: exame sorogrupável, sorogrupo em branco")
  add(c3b, "INCONSISTENTE", "Alta", paste0("INCONSISTENTE: meningococo, mas o exame deu ",
                                           ifelse(agente != "", agente, "outro agente")))
  if (PENDENCIA_SEM_SOROGRUPO) {
    add(c3, "SEM SOROGRUPO", "Baixa", "SEM SOROGRUPO: exame sorogrupável negativo/não reagente")
    add(c4, "SEM SOROGRUPO", "Baixa", paste0("SEM SOROGRUPO: confirmado por ", tolower(criterio), ", que não sorogrupa"))
  }
  add(c5, "NÃO IDENTIFICADO", "Média", "NÃO IDENTIFICADO: meningococo sem exame nem critério")
  # etiologia que não bate com o agente do exame (qualquer etiologia)
  cod_et <- dplyr::case_when(et == "Pneumococo" ~ "7", et == "Hemofilo" ~ "6", TRUE ~ NA_character_)
  nao_bate <- vapply(seq_len(n), function(i) !is.na(cod_et[i]) && length(esp_ag[[i]]) > 0 && !(cod_et[i] %in% esp_ag[[i]]),
                     logical(1))
  add(conf & nao_bate, "INCONSISTENTE", "Alta", paste0("INCONSISTENTE: etiologia ", etiologia, ", mas o exame identificou ", agente))
  bate <- vapply(seq_len(n), function(i) is.na(cod_et[i]) || cod_et[i] %in% esp_ag[[i]], logical(1))
  add(conf & !is.na(cod_et) & !bate & !nao_bate & !crit_sorog, "INCONSISTENTE", "Média",
      paste0("INCONSISTENTE: ", etiologia, " sem exame nem critério laboratorial que confirme"))
  tem_esp <- vapply(esp_ag, length, 0L) > 0
  add(conf & (tb | et %in% c("Outra bacteria", "Outra etiologia")) & tem_esp, "INCONSISTENTE", "Alta",
      paste0("INCONSISTENTE: etiologia ", etiologia, ", mas o exame identificou ", agente))
  add(conf & et == "Asseptica" & agente != "", "INCONSISTENTE", "Alta",
      paste0("INCONSISTENTE: asséptica, mas o exame identificou ", agente))
  add(conf & et == "Asseptica" & agente == "" & bc_res != "", "INCONSISTENTE", "Média",
      paste0("INCONSISTENTE: asséptica, mas a bacterioscopia mostrou ", bc_res))
  # etiologia não especificada, em branco ou sem o agente
  nid <- conf & et %in% c("Nao especificada", "Nao determinada", "Sem informacao")
  rot_nid <- ifelse(et == "Nao especificada", "etiologia não especificada", "etiologia em branco")
  add(nid & agente != "", "RECUPERÁVEL", "Alta", paste0("RECUPERÁVEL: ", rot_nid, ", mas o exame identificou ", agente))
  add(nid & agente == "" & bc_res != "", "NÃO IDENTIFICADO", ifelse(obito, "Alta", "Média"),
      .ob(paste0("NÃO IDENTIFICADO: ", rot_nid, "; só bacterioscopia (", bc_res, ")")))
  add(nid & agente == "" & bc_res == "" & algum_exame, "NÃO IDENTIFICADO", ifelse(obito, "Alta", "Média"),
      .ob(paste0("NÃO IDENTIFICADO: ", rot_nid, "; exames sem agente")))
  add(nid & !algum_exame, "NÃO IDENTIFICADO", ifelse(obito, "Alta", "Média"),
      .ob(paste0("NÃO IDENTIFICADO: ", rot_nid, ", sem exame", ifelse(pun %in% "2", " (punção não realizada)", ""))))
  add(conf & et == "Outra bacteria" & !tb & !bac_esp & !tem_esp, "NÃO IDENTIFICADO", ifelse(obito, "Alta", "Média"),
      .ob(paste0("NÃO IDENTIFICADO: outras bactérias, ", ifelse(bac_n %in% "81", "agente não determinado", "agente em branco"),
                 ifelse(bc_res != "", paste0(" (bacterioscopia: ", bc_res, ")"), ""))))
  add(conf & et == "Outra etiologia" & !eti_esp & !tem_esp, "NÃO IDENTIFICADO", "Média",
      "NÃO IDENTIFICADO: outra etiologia, agente em branco")
  if (PENDENCIA_VIRAL_SEM_AGENTE)
    add(conf & et == "Asseptica" & !vir_esp & agente == "", "NÃO IDENTIFICADO", "Baixa",
        "NÃO IDENTIFICADO: asséptica sem vírus identificado")
  # fichas encerradas que se contradizem
  add(desc & agente != "", "INCONSISTENTE", "Alta", paste0("INCONSISTENTE: descartado, mas o exame identificou ", agente))
  add(conf & tem_sorog & et != "Meningococo", "INCONSISTENTE", "Média",
      paste0("INCONSISTENTE: sorogrupo ", SOROGRUPOS[sor_n], " preenchido, mas a etiologia não é meningococo"))
  add(pun %in% "2" & lcr_feito, "INCONSISTENTE", "Média", "INCONSISTENTE: punção 'não realizada', mas há exame de LCR")
  add(!is.na(dt_sin) & !is.na(dt_not) & dt_sin > dt_not, "INCONSISTENTE", "Média",
      "INCONSISTENTE: início dos sintomas depois da notificação")
  add(!is.na(dt_enc) & !is.na(dt_not) & dt_enc < dt_not, "INCONSISTENTE", "Média", "INCONSISTENTE: encerramento antes da notificação")
  add(!is.na(dt_evo) & !is.na(dt_sin) & dt_evo < dt_sin, "INCONSISTENTE", "Média", "INCONSISTENTE: evolução antes do início dos sintomas")
  add(!is.na(dt_nasc) & !is.na(dt_sin) & dt_nasc > dt_sin, "INCONSISTENTE", "Média", "INCONSISTENTE: nascimento depois dos sintomas")
  # campos importantes em branco
  if (PENDENCIA_EVOLUCAO)
    add(conf & evolucao %in% c("Em branco", "Ignorado"), "CAMPO EM BRANCO", "Baixa",
        ifelse(evolucao == "Ignorado", "IGNORADO: evolução", "EM BRANCO: evolução"))
  add(conf & obito & is.na(dt_evo) & "MED_DT_EVO" %in% names(x), "CAMPO EM BRANCO", "Média", "EM BRANCO: data do óbito")
  add(conf & is.na(crit_n), "CAMPO EM BRANCO", "Média", "EM BRANCO: critério de confirmação")
  if (tem_quimio)
    add(conf & et %in% c("Meningococo", "Hemofilo") & !(quimio %in% c("1", "2")), "CAMPO EM BRANCO", "Média",
        "EM BRANCO: quimioprofilaxia dos contatos")
  if (PENDENCIA_CRITERIO_EXAME) {
    sem_res <- vapply(seq_len(n), function(i) {
      if (!conf[i] || is.na(crit_n[i])) return(FALSE)
      cols <- EXAMES$col[EXAMES$crit == crit_n[i]]
      length(cols) > 0 && !any(vapply(cols, function(cc) feito[[cc]][i], logical(1)))
    }, logical(1))
    add(sem_res & !c2, "CAMPO EM BRANCO", "Baixa", paste0("EM BRANCO: resultado do exame do critério (", tolower(criterio), ")"))
  }
  add(n_reg > 1, "DUPLICIDADE", "Média", paste0("DUPLICIDADE: ", n_reg, " registros com o mesmo número e data"))
  
  P <- if (length(P)) do.call(rbind, P) else data.frame(id = integer(), cat = character(), pri = character(),
                                                        rot = character())
  P <- P[order(P$id, PRIOR[P$pri], match(P$cat, CATS$cat)), ]
  princ <- P[!duplicated(P$id), ]
  rot_all <- tapply(P$rot, P$id, function(v) paste(unique(v), collapse = "  ·  "))
  n_pend  <- tapply(P$id,  P$id, length)
  
  idade <- {
    ni <- .txt(g("NU_IDADE_N")); tp <- substr(ni, 1, 1); vl <- suppressWarnings(as.integer(substr(ni, 2, 4)))
    lab <- ifelse(!is.na(vl) & tp == "4", paste(vl, "a"), ifelse(!is.na(vl) & tp == "3", paste(vl, "m"),
                                                                 ifelse(!is.na(vl) & tp == "2", paste(vl, "d"), ifelse(!is.na(vl) & tp == "1", paste(vl, "h"), NA))))
    id2 <- suppressWarnings(as.numeric(g("idade")))
    ifelse(is.na(lab) & !is.na(id2), paste(id2, "a"), ifelse(is.na(lab), "", lab))
  }
  out <- data.frame(stringsAsFactors = FALSE,
                    chave = chave, nu = nu, nome = .txt(g("NM_PACIENT")), dt_sin = dt_sin, dt_not = dt_not,
                    dt_enc = dt_enc, dias = dias, idade = idade, sexo = .txt(g("CS_SEXO")),
                    muni = .titulo(.txt(g("MUNI_RESID"))), gve = .txt(g("GVE_RESID")), drs = .txt(g("DRS_RESID")),
                    classif = classif, evolucao = evolucao, criterio = criterio, exames = exames_txt, etiologia = etiologia,
                    sorogrupo = unname(sorogrupo), sem = .semana(dref), dref = dref,
                    cat = "", pri = "", pend = "", n_pend = 0L)
  out$cat[princ$id] <- princ$cat
  out$pri[princ$id] <- princ$pri
  ids <- as.integer(names(rot_all))
  out$pend[ids] <- rot_all; out$n_pend[ids] <- as.integer(n_pend)
  out$estado <- ifelse(out$cat != "", out$cat, ifelse(out$classif == "Descartado", "DESCARTADO", "OK"))
  
  # ---- demais colunas da ficha (só na rodada atual)
  if (demais) for (k in seq_len(nrow(DEMAIS))) {
    orig <- strsplit(DEMAIS$orig[k], "|", fixed = TRUE)[[1]]; tem <- orig[orig %in% names(x)]
    if (!length(tem)) next
    v <- x[[tem[1]]]; tp <- DEMAIS$tipo[k]
    out[[DEMAIS$id[k]]] <- switch(tp,
                                  data = .data(v),
                                  sn = { if (grepl("^[A-Z_]+$", tem[1])) { c0 <- .cod(v); unname(ifelse(c0 %in% names(SIM_NAO), SIM_NAO[c0], NA)) }
                                    else .acentos(.txt(v)) },
                                  forma = { c0 <- .cod(v); unname(ifelse(c0 %in% names(FORMAS), FORMAS[c0], ifelse(is.na(c0), NA, paste("cód.", c0)))) },
                                  sorogrupo = { c0 <- .cod(v); unname(ifelse(c0 %in% names(SOROGRUPOS), SOROGRUPOS[c0], NA)) },
                                  exame = { c0 <- .cod(v); unname(ifelse(is.na(c0), NA, ifelse(c0 %in% COD_NAO_FEITO,
                                                                                               ifelse(c0 == "61", "não realizado", "ignorado"), rotulo_res(c0, "sorog")))) },
                                  exame_bc = { c0 <- .cod(v); unname(ifelse(is.na(c0), NA, ifelse(c0 %in% COD_NAO_FEITO,
                                                                                                  ifelse(c0 == "61", "não realizado", "ignorado"), rotulo_res(c0, "bc")))) },
                                  .acentos(.txt(v)))
  }
  out
}

## ---- 6. RODADA ATUAL ------------------------------------------------------------
snaps <- lista_snapshots()
if (!is.na(ARQ_SNAPSHOT)) {
  if (!file.exists(ARQ_SNAPSHOT)) stop("Arquivo não encontrado: ", ARQ_SNAPSHOT, call. = FALSE)
  arq_atual <- ARQ_SNAPSHOT
  d_atual <- as.Date(stringi::stri_extract_first_regex(basename(arq_atual), "\\d{4}_\\d{2}_\\d{2}"), "%Y_%m_%d")
  if (is.na(d_atual)) d_atual <- as.Date(file.mtime(arq_atual))
} else {
  if (!nrow(snaps)) stop("Nenhum bd_meningite_*.RData em:\n  ", DIR_SNAPSHOT, call. = FALSE)
  arq_atual <- snaps$arq[nrow(snaps)]; d_atual <- snaps$data[nrow(snaps)]
}
SEM_ATUAL <- .semana(d_atual)
ANO_REF   <- lubridate::epiyear(d_atual)

# pasta de saída e planilha (antes de qualquer conta: se a planilha estiver aberta, para já)
.grava_ok <- function(p) tryCatch({
  dir.create(p, recursive = TRUE, showWarnings = FALSE)
  f <- file.path(p, paste0(".argos_teste_", Sys.getpid())); writeLines("ok", f); file.remove(f)
}, error = function(e) FALSE, warning = function(w) FALSE)
if (!.grava_ok(PASTA_SAIDA))
  stop("Não consegui gravar na pasta do Argos:\n  ", PASTA_SAIDA,
       "\n  Veja se o X: está conectado (rede ou VPN) e se você tem permissão de gravação nessa pasta.",
       "\n  Nada foi gravado.", call. = FALSE)
PASTA <- PASTA_SAIDA
ARQ_XLSX <- file.path(PASTA, if (PREVIA) sub("\\.xlsx$", "_PREVIA.xlsx", NOME_PLANILHA) else NOME_PLANILHA)
ARQ_HIST <- file.path(PASTA, "argos_historico.rds")
.aberta <- function(f) {
  if (!file.exists(f)) return(FALSE)
  if (file.exists(file.path(dirname(f), paste0("~$", basename(f))))) return(TRUE)   # trava do Excel
  !isTRUE(tryCatch({ con <- file(f, open = "r+b"); close(con); TRUE }, error = function(e) FALSE,
                   warning = function(w) FALSE))
}
if (.aberta(ARQ_XLSX))
  stop("A planilha está aberta (por você ou por alguém da rede):\n  ", ARQ_XLSX,
       "\n  Feche-a e rode o Argos de novo. Nada foi alterado.", call. = FALSE)

.diga(">> Exportação do Sinan: ", basename(arq_atual), "  (base de ", format(d_atual, "%d/%m/%Y"),
      ", SE ", lubridate::epiweek(d_atual), "/", ANO_REF, ")")
E <- estado(ler_snapshot(arq_atual), d_atual)
if (is.null(E)) stop("Nenhuma notificação na janela do Argos.", call. = FALSE)
.diga("   ", .n0(nrow(E)), " notificações na janela (",
      if (is.na(ANOS)) "todos os anos" else paste0(ANO_REF - ANOS + 1, if (ANOS > 1) paste0(" a ", ANO_REF) else ""),
      "); ", .n0(sum(E$cat != "")), " com pendência")

## ---- 7. HISTÓRICO -----------------------------------------------------------------
COLS_HIST <- c("chave", "nu", "nome", "dt_sin", "dt_not", "dref", "drs", "muni", "classif", "evolucao",
               "etiologia", "sorogrupo", "criterio", "cat", "pri", "pend", "n_pend")
foto <- function(Est, d) {
  h <- Est[Est$cat != "", COLS_HIST]
  cbind(data.frame(sem_rodada = rep(.semana(d), nrow(h)), data_base = rep(d, nrow(h))), h)
}
MEM <- if (file.exists(ARQ_HIST)) tryCatch(readRDS(ARQ_HIST), error = function(e) NULL) else NULL
hist <- if (is.data.frame(MEM)) MEM else MEM$hist          # (versões antigas guardavam só o histórico)
NOTAS_MEM <- if (is.list(MEM) && !is.data.frame(MEM)) MEM$notas else NULL
if (is.null(hist)) hist <- foto(E, d_atual)[0, ]
if (!"dref" %in% names(hist)) hist$dref <- dplyr::coalesce(hist$dt_sin, hist$dt_not)
hist <- hist[hist$sem_rodada != SEM_ATUAL & hist$sem_rodada < SEM_ATUAL, ]   # a rodada desta semana é refeita

# semanas que faltam no histórico: reconstrói pelas exportações antigas do Sinan
alvo <- SEM_ATUAL - 7 * seq_len(SEMANAS_HISTORICO - 1)
faltam <- setdiff(as.character(alvo), as.character(unique(hist$sem_rodada)))
if (length(faltam) && nrow(snaps)) {
  snaps$sem <- .semana(snaps$data)
  cand <- snaps[as.character(snaps$sem) %in% faltam & snaps$data < d_atual, ]
  cand <- cand[!duplicated(cand$sem, fromLast = TRUE), ]  # a última exportação de cada semana
  if (nrow(cand)) .diga(">> Reconstruindo ", nrow(cand), " semana(s) anteriores a partir das exportações antigas...")
  for (k in seq_len(nrow(cand))) {
    .diga("   ", basename(cand$arq[k]))
    Ek <- tryCatch(estado(ler_snapshot(cand$arq[k]), cand$data[k], demais = FALSE), error = function(e) {
      .diga("   [aviso] não consegui ler ", basename(cand$arq[k]), ": ", conditionMessage(e)); NULL })
    if (!is.null(Ek)) hist <- dplyr::bind_rows(hist, foto(Ek, cand$data[k]))
    rm(Ek); invisible(gc())
  }
}
hist <- dplyr::bind_rows(hist, foto(E, d_atual))
hist <- hist[hist$sem_rodada >= SEM_ATUAL - 7 * 156, ]    # guarda até 3 anos de rodadas
hist <- hist[order(hist$sem_rodada, hist$chave), ]
rodadas <- sort(unique(hist$sem_rodada))
data_rodada <- tapply(hist$data_base, as.character(hist$sem_rodada), max)
data_rodada <- as.Date(data_rodada[as.character(rodadas)], origin = "1970-01-01")
names(data_rodada) <- as.character(rodadas)
r_ant <- if (sum(rodadas < SEM_ATUAL)) max(rodadas[rodadas < SEM_ATUAL]) else NA
d_ant <- if (!is.na(r_ant)) data_rodada[as.character(r_ant)] else NA
H_ant <- if (!is.na(r_ant)) hist[hist$sem_rodada == r_ant, ] else hist[0, ]
R_SHOW <- tail(rodadas, SEMANAS_HISTORICO)

## ---- 8. A LINHA DE CADA FICHA: situação, histórico e o que mudou ---------------------
HK <- split(hist, hist$chave)
na_jan_h <- vapply(HK, function(h) .na_janela(h$dref[nrow(h)], ANO_REF), logical(1))
chaves <- union(E$chave[E$cat != ""], names(HK)[na_jan_h])
rk <- function(p) if (length(p) && !is.na(p) && p %in% names(PRIOR)) 4 - PRIOR[[p]] else 0
.mud <- function(a, b, rot = "") ifelse(!is.na(a) & !is.na(b) & a != b, paste0(rot, a, " → ", b), NA)
iE <- match(chaves, E$chave)
info <- lapply(seq_along(chaves), function(q) {
  k <- chaves[q]; h <- HK[[k]]; h <- h[order(h$sem_rodada), ]
  a <- if (is.na(iE[q])) NULL else E[iE[q], ]
  est <- if (is.null(a)) "FORA DA BASE" else a$estado
  pend <- est %in% CATS$cat
  rp <- h$sem_rodada; prim <- h[1, ]; ult <- h[nrow(h), ]
  prev <- if (!is.na(r_ant)) h[h$sem_rodada == r_ant, ] else h[0, ]
  # rodada em que saiu da lista
  depois <- rodadas[rodadas > max(rp)]
  quando <- if (!pend && length(depois)) data_rodada[as.character(min(depois))] else as.Date(NA)
  sit <- if (est == "FORA DA BASE") "SAIU DA BASE"
  else if (!pend) { if (nrow(prev) && !is.na(r_ant)) "RESOLVIDA NESTA SEMANA" else "RESOLVIDA" }
  else if (is.na(r_ant)) "PENDENTE"
  else if (!nrow(prev)) { if (any(rp < SEM_ATUAL)) "VOLTOU" else "NOVA" }
  else if (rk(a$pri) > rk(prev$pri) || (a$cat == prev$cat && a$n_pend > prev$n_pend)) "PIOROU"
  else if (rk(a$pri) < rk(prev$pri) || (a$cat == prev$cat && a$n_pend < prev$n_pend)) "MELHOROU"
  else if (a$cat != prev$cat) "MUDOU" else "SEM MUDANÇA"
  # semanas seguidas na lista (contando esta)
  seg <- 0L
  if (pend) for (r in rev(as.character(c(rodadas[rodadas < SEM_ATUAL], SEM_ATUAL))))
    if (r == as.character(SEM_ATUAL) || r %in% as.character(rp)) seg <- seg + 1L else break
  # texto curto do que mudou desde a rodada anterior
  desde <- switch(sit,
                  "PENDENTE" = "Primeira semana do Argos",
                  "NOVA" = if (!is.na(d_ant) && !is.na(a$dt_not) && a$dt_not > d_ant) "Notificação nova" else "Entrou na lista nesta semana",
                  "VOLTOU" = paste0("Voltou à lista (tinha saído em ", .dm(data_rodada[as.character(min(rodadas[rodadas > max(rp[rp < SEM_ATUAL])]))]), ")"),
                  "RESOLVIDA NESTA SEMANA" = paste0("Resolvida nesta semana (era ", .rot_estado(ult$cat), ")"),
                  "RESOLVIDA" = paste0("Resolvida em ", .dm(quando), " (era ", .rot_estado(ult$cat), ")"),
                  "SAIU DA BASE" = "Não está mais na exportação do Sinan",
                  { base <- if (a$cat == prev$cat) paste0(CATS$segue[match(a$cat, CATS$cat)], " (", seg, "ª semana)")
                  else paste0(.rot_estado(prev$cat), " → ", .rot_estado(a$cat))
                  ext <- c(.mud(prev$classif, a$classif), .mud(prev$evolucao, a$evolucao, "evolução: "),
                           .mud(prev$etiologia, a$etiologia, "etiologia: "))
                  ext <- ext[!is.na(ext)]
                  if (length(ext)) paste0(base, "; ", paste(ext, collapse = "; ")) else base })
  # situação em cada uma das últimas rodadas
  cel <- vapply(R_SHOW, function(r) {
    if (r == SEM_ATUAL) return(est)
    j <- match(r, rp)
    if (!is.na(j)) return(h$cat[j])
    if (r > prim$sem_rodada) (if (est %in% c("OK", "DESCARTADO")) est else "OK") else ""
  }, character(1))
  # o que mudou, rodada a rodada (desde a primeira vez na lista)
  rr <- rodadas[rodadas >= prim$sem_rodada]
  ultimo <- NULL; mud <- character()
  for (r in as.character(rr)) {
    rd <- as.Date(r)
    s <- if (rd == SEM_ATUAL) { if (is.null(a)) NULL else a[, c("classif", "evolucao", "etiologia", "estado")] }
    else { j <- match(rd, rp)
    if (!is.na(j)) data.frame(classif = h$classif[j], evolucao = h$evolucao[j], etiologia = h$etiologia[j],
                              estado = h$cat[j], stringsAsFactors = FALSE)
    else if (!is.null(a)) { s0 <- a[, c("classif", "evolucao", "etiologia")]; s0$estado <- if (est %in% c("OK", "DESCARTADO")) est else "OK"; s0 }
    else NULL }
    if (is.null(s)) next
    if (!is.null(ultimo)) {
      m <- c(.mud(ultimo$classif, s$classif), .mud(ultimo$evolucao, s$evolucao, "evolução: "),
             .mud(ultimo$etiologia, s$etiologia, "etiologia: "), .mud_estado(ultimo$estado, s$estado))
      m <- m[!is.na(m)]
      if (length(m)) mud <- c(mud, paste0(.dm(data_rodada[r]), ": ", paste(m, collapse = "; ")))
    }
    ultimo <- s
  }
  if (is.null(a)) mud <- c(mud, paste0(.dm(d_atual), ": a notificação não está mais na exportação do Sinan"))
  list(sit = sit, quando = quando, desde = desde, seg = seg, n_rod = length(rp),
       na_lista = data_rodada[as.character(prim$sem_rodada)], cel = cel,
       mudou = if (length(mud)) paste(rev(tail(mud, 6)), collapse = " | ") else "—",
       ult = ult)
})
names(info) <- chaves
.v <- function(campo, tipo) vapply(info, function(z) z[[campo]], tipo)
A <- data.frame(stringsAsFactors = FALSE, chave = chaves,
                sit = .v("sit", ""), desde = .v("desde", ""), seg = .v("seg", 0L), n_rod = .v("n_rod", 0L),
                mudou = .v("mudou", ""))
A$quando   <- as.Date(vapply(info, function(z) as.numeric(z$quando), 0), origin = "1970-01-01")
A$na_lista <- as.Date(vapply(info, function(z) as.numeric(z$na_lista), 0), origin = "1970-01-01")
CEL <- do.call(rbind, lapply(info, `[[`, "cel")); if (is.null(dim(CEL))) CEL <- matrix(CEL, ncol = length(R_SHOW))
# dados do caso: da exportação atual; se saiu da base, do último registro do histórico
ULT <- do.call(rbind, lapply(info, `[[`, "ult"))
B <- E[iE, ]
fora <- is.na(iE)
for (cc in c("nu", "nome", "dt_sin", "dt_not", "drs", "muni", "classif", "evolucao", "etiologia", "sorogrupo",
             "criterio", "dref"))
  if (cc %in% names(ULT)) B[[cc]][fora] <- ULT[[cc]][fora]
B$chave <- chaves; B$sem <- .semana(B$dref)
resolv <- A$sit %in% c("RESOLVIDA NESTA SEMANA", "RESOLVIDA", "SAIU DA BASE")
B$pri[resolv] <- ""
B$cat_cor <- ifelse(resolv, ifelse(A$sit == "SAIU DA BASE", "FORA DA BASE", ifelse(fora, "OK", B$estado)), B$cat)
B$cat_txt <- ifelse(resolv, .rot_estado(B$cat_cor), B$pend)          # o que era fica em "Desde a última semana"
AC <- cbind(A, B[, setdiff(names(B), "chave")])
ORD_SIT <- SITUACOES$sit
AC$grupo <- ifelse(resolv, ifelse(A$sit == "SAIU DA BASE", 3, 2), 1)
AC <- AC[order(-as.numeric(AC$sem), AC$grupo, -as.numeric(AC$dref), AC$nome), ]
CEL <- CEL[match(AC$chave, chaves), , drop = FALSE]

## ---- 9. O QUE A EQUIPE ESCREVEU NA PLANILHA ------------------------------------------
SH <- "Acompanhamento"
L_CAB <- 5                                             # linha dos cabeçalhos; dados a partir da 6
EQUIPE <- c("Contato", "Responsável", "Data do contato", "Observações")
ABAS_ARGOS <- c(SH, "Resumo", "Como ler", "listas")
COLS_FIXAS <- c("SE", "Nome", "Nº SINAN", "Início dos sintomas", "Situação", "Pendência", "Sorogrupo",
                "Desde a última semana epidemiológica", "Semanas com pendência",
                "Prioridade", "Categoria", "O que falta", "Ação sugerida", "Desde a última rodada",   # (versão 1.1)
                "Semanas seguidas na lista",
                "Classificação", "Evolução", "Critério de confirmação", "Exames registrados", "Etiologia",
                "Notificação", "Encerramento", "Dias desde a notificação", "Idade", "Sexo",
                "Município de residência", "GVE", "DRS", "Na lista desde", "Rodadas com pendência",
                "O que mudou (mais recente primeiro)", "chave", DEMAIS$rot)
.eh_col_argos <- function(cab) cab %in% COLS_FIXAS | grepl("^SE \\d{2}\\s*\\n?\\s*\\d{2}/\\d{2}$", cab)
ED <- list(val = NULL, cols = character(), extras = NULL, abas = character())
if (file.exists(ARQ_XLSX)) {
  ED$abas <- tryCatch(openxlsx::getSheetNames(ARQ_XLSX), error = function(e) character())
  if (SH %in% ED$abas) {
    m <- tryCatch(openxlsx::read.xlsx(ARQ_XLSX, sheet = SH, startRow = L_CAB, colNames = FALSE,
                                      skipEmptyRows = FALSE, skipEmptyCols = FALSE),
                  error = function(e) { .diga("   [aviso] não consegui ler a planilha anterior: ", conditionMessage(e)); NULL })
    if (!is.null(m) && nrow(m) > 1) {
      cab <- as.character(unlist(m[1, ])); cab[is.na(cab)] <- ""
      dd <- m[-1, , drop = FALSE]
      ck <- which(cab == "chave")[1]
      if (is.na(ck)) {
        .diga("   [aviso] a coluna oculta 'chave' sumiu da planilha: não dá para ligar as anotações às fichas")
      } else {
        tem_dado <- vapply(seq_along(cab), function(j) any(!is.na(dd[[j]]) & nzchar(trimws(as.character(dd[[j]])))), logical(1))
        cab[!nzchar(cab) & tem_dado] <- paste0("Coluna da equipe ", which(!nzchar(cab) & tem_dado))
        uc <- which((cab %in% EQUIPE | (!.eh_col_argos(cab) & nzchar(cab))) & !duplicated(cab))
        ED$cols <- cab[uc]
        val <- dd[, uc, drop = FALSE]; names(val) <- cab[uc]
        for (j in names(val)) {                        # tudo vira texto; datas como dd/mm/aaaa
          if (grepl("^Data", j) && is.numeric(val[[j]])) val[[j]] <- format(openxlsx::convertToDate(val[[j]]), "%d/%m/%Y")
          val[[j]] <- as.character(val[[j]])
        }
        chv <- as.character(dd[[ck]])
        sep <- grepl("^(SEMANA EPIDEMIOLÓGICA|LINHAS ACRESCENTADAS)", as.character(dd[[1]]))
        algo <- apply(dd, 1, function(r) any(!is.na(r) & nzchar(trimws(as.character(r)))))
        ED$val <- cbind(data.frame(chave = chv, stringsAsFactors = FALSE), val)[!is.na(chv), , drop = FALSE]
        ED$val <- ED$val[!duplicated(ED$val$chave), , drop = FALSE]
        ex <- is.na(chv) & !sep & algo
        if (any(ex)) { ED$extras <- dd[ex, , drop = FALSE]; names(ED$extras) <- cab }
        n_anot <- if (length(ED$cols)) sum(apply(ED$val[, ED$cols, drop = FALSE], 1, function(r) any(!is.na(r)))) else 0
        .diga("   planilha anterior lida: anotações em ", n_anot, " ficha(s)",
              if (length(setdiff(ED$cols, EQUIPE))) paste0("; colunas criadas pela equipe: ",
                                                           paste(setdiff(ED$cols, EQUIPE), collapse = ", ")) else "",
              if (!is.null(ED$extras)) paste0("; ", nrow(ED$extras), " linha(s) acrescentada(s) à mão") else "")
      }
    }
  }
}
# As anotações também ficam na memória do Argos (argos_historico.rds). Vale sempre o que está
# na planilha; a memória só entra para fichas que não estavam nela (saíram e voltaram, ou a
# planilha foi apagada). Anotação apagada na planilha é apagada também da memória.
ED$todas <- if (!is.null(ED$val)) ED$val$chave else character()
notas_ant <- NOTAS_MEM
if (!is.null(ED$val)) {
  nv <- ED$val[apply(ED$val[, setdiff(names(ED$val), "chave"), drop = FALSE], 1, function(r) any(!is.na(r) & nzchar(r))), , drop = FALSE]
  notas_ant <- dplyr::bind_rows(nv, if (!is.null(notas_ant)) notas_ant[!notas_ant$chave %in% ED$todas, , drop = FALSE])
}
if (!is.null(notas_ant) && !nrow(notas_ant)) notas_ant <- NULL
COLS_EQ <- unique(c(EQUIPE, ED$cols,
                    if (!file.exists(ARQ_XLSX) && !is.null(notas_ant)) setdiff(names(notas_ant), "chave")))
EQV <- data.frame(chave = AC$chave, stringsAsFactors = FALSE)
for (j in COLS_EQ) EQV[[j]] <- if (!is.null(ED$val) && j %in% names(ED$val)) ED$val[[j]][match(AC$chave, ED$val$chave)] else NA_character_
if (!is.null(notas_ant)) {
  usa <- !(EQV$chave %in% ED$todas)
  for (j in intersect(COLS_EQ, names(notas_ant)))
    EQV[[j]][usa] <- as.character(notas_ant[[j]][match(EQV$chave[usa], notas_ant$chave)])
  n_mem <- sum(usa & EQV$chave %in% notas_ant$chave)
  if (n_mem) .diga("   anotações recuperadas da memória do Argos: ", n_mem, " ficha(s)")
}

## ---- 10. A PLANILHA ----------------------------------------------------------------
FONTE <- "Calibri"
.st <- function(..., fontSize = 10) openxlsx::createStyle(fontName = FONTE, fontSize = fontSize, ...)
S_TIT   <- .st(fontSize = 18, textDecoration = "bold", fontColour = "#1F3864")
S_PREV  <- .st(fontSize = 18, textDecoration = "bold", fontColour = "#C00000")
S_SUB   <- .st(fontColour = "#595959")
S_RES   <- .st(fontColour = "#1F3864", textDecoration = "bold")
S_GRUPO <- .st(textDecoration = "bold", fontColour = "#FFFFFF", fgFill = "#1F3864", halign = "center",
               valign = "center", border = "LeftRight", borderColour = "#FFFFFF")
S_GRUPO_EQ <- .st(textDecoration = "bold", fontColour = "#7F6000", fgFill = "#FFE699", halign = "center",
                  valign = "center", border = "LeftRight", borderColour = "#FFFFFF")
S_CAB   <- .st(textDecoration = "bold", fontColour = "#1F3864", fgFill = "#DCE3EE", halign = "center",
               valign = "center", wrapText = TRUE, border = "TopBottomLeftRight", borderColour = "#FFFFFF")
S_CAB_EQ <- .st(textDecoration = "bold", fontColour = "#7F6000", fgFill = "#FFF2CC", halign = "center",
                valign = "center", wrapText = TRUE, border = "TopBottomLeftRight", borderColour = "#FFFFFF")
S_DADO  <- .st(valign = "center", border = "Bottom", borderColour = "#D9D9D9")
S_WRAP  <- openxlsx::createStyle(wrapText = TRUE, valign = "center")
S_CENT  <- openxlsx::createStyle(halign = "center")
S_DATA  <- openxlsx::createStyle(numFmt = "dd/mm/yyyy", halign = "center")
S_NEG   <- openxlsx::createStyle(textDecoration = "bold")
S_SEP   <- .st(fontSize = 11, textDecoration = "bold", fontColour = "#FFFFFF", fgFill = "#2F5597",
               valign = "center", border = "TopBottom", borderColour = "#1F3864", borderStyle = "medium")
S_SEP_EQ <- .st(fontSize = 11, textDecoration = "bold", fontColour = "#7F6000", fgFill = "#FFE699", valign = "center")
S_EQUIPE <- .st(fgFill = "#FFFBEA", valign = "center", wrapText = TRUE, border = "Bottom", borderColour = "#D9D9D9")
S_RESOLV <- openxlsx::createStyle(fgFill = "#F3F9EF")
S_FORA   <- openxlsx::createStyle(fgFill = "#F7F7F7", fontColour = "#7F7F7F")
S_CINZA  <- openxlsx::createStyle(fontColour = "#808080", textDecoration = "italic")
.cor <- function(fundo, letra, neg = TRUE, centro = TRUE)
  openxlsx::createStyle(fgFill = fundo, fontColour = letra, textDecoration = if (neg) "bold" else NULL,
                        halign = if (centro) "center" else NULL, valign = "center", wrapText = TRUE)
COR_PRI <- list("Alta" = .st(fontColour = "#C00000", textDecoration = "bold", halign = "center"),
                "Média" = .st(fontColour = "#C65911", textDecoration = "bold", halign = "center"),
                "Baixa" = .st(fontColour = "#7F7F7F", halign = "center"))
TODOS_ESTADOS <- rbind(CATS[, c("cat", "curto", "fundo", "letra")], OUTROS_ESTADOS[, c("cat", "curto", "fundo", "letra")])
.se_lab <- function(s) ifelse(lubridate::epiyear(s) == ANO_REF, sprintf("SE %02d", lubridate::epiweek(s)),
                              sprintf("SE %02d/%s", lubridate::epiweek(s), substr(lubridate::epiyear(s), 3, 4)))
.altura <- function(df, larg, wrap, max_l = 6) {
  l <- rep(1, nrow(df))
  for (j in which(wrap)) {
    v <- as.character(df[[j]]); v[is.na(v)] <- ""
    l <- pmax(l, ceiling(nchar(v) / (larg[j] * 1.2)))
  }
  14 * pmin(l, max_l) + 4
}
.cabecalho <- function(wb, sh, titulo, col_previa) {
  openxlsx::writeData(wb, sh, paste0("ARGOS  ·  ", titulo), startRow = 1, startCol = 1)
  openxlsx::addStyle(wb, sh, S_TIT, rows = 1, cols = 1)
  if (PREVIA) {
    openxlsx::writeData(wb, sh, "PRÉVIA COM DADOS FICTÍCIOS", startRow = 1, startCol = col_previa)
    openxlsx::addStyle(wb, sh, S_PREV, rows = 1, cols = col_previa)
  }
  openxlsx::writeData(wb, sh, paste0(
    "Base do Sinan de ", format(d_atual, "%d/%m/%Y"), " (SE ", lubridate::epiweek(d_atual), "/", ANO_REF, ")  ·  ",
    if (is.na(ANOS)) "todos os anos" else if (ANOS == 1) paste0("início dos sintomas em ", ANO_REF)
    else paste0("início dos sintomas de ", ANO_REF - ANOS + 1, " a ", ANO_REF),
    "  ·  atualizada em ", format(Sys.time(), "%d/%m/%Y %H:%M"),
    "  ·  DADOS NOMINAIS: uso restrito à vigilância"), startRow = 2, startCol = 1)
  openxlsx::addStyle(wb, sh, S_SUB, rows = 2, cols = 1)
  openxlsx::setRowHeights(wb, sh, rows = 1:3, heights = c(30, 16, 16))
}
.grupos <- function(wb, sh, grupos, linha = 4) {
  r <- rle(grupos); fim <- cumsum(r$lengths); ini <- fim - r$lengths + 1
  for (k in seq_along(r$values)) {
    if (r$lengths[k] > 1) openxlsx::mergeCells(wb, sh, cols = ini[k]:fim[k], rows = linha)
    openxlsx::writeData(wb, sh, r$values[k], startRow = linha, startCol = ini[k])
    openxlsx::addStyle(wb, sh, if (grepl("^EQUIPE", r$values[k])) S_GRUPO_EQ else S_GRUPO,
                       rows = linha, cols = ini[k]:fim[k], gridExpand = TRUE)
  }
}

# abas criadas pela equipe: a planilha anterior é carregada para mantê-las
abas_eq <- setdiff(ED$abas, ABAS_ARGOS)
wb <- NULL
if (length(abas_eq)) wb <- tryCatch({
  w <- openxlsx::loadWorkbook(ARQ_XLSX)
  for (s in intersect(ABAS_ARGOS, names(w))) openxlsx::removeWorksheet(w, s)
  .diga("   abas criadas pela equipe mantidas: ", paste(abas_eq, collapse = ", "))
  w
}, error = function(e) {
  .diga("   [aviso] não consegui manter as abas da equipe (", paste(abas_eq, collapse = ", "),
        "); elas continuam na cópia em backup/"); NULL })
if (is.null(wb)) wb <- openxlsx::createWorkbook(creator = "Argos (CVE/SES-SP)")
openxlsx::modifyBaseFont(wb, fontSize = 10, fontName = FONTE)

# ---------- ABA ACOMPANHAMENTO
openxlsx::addWorksheet(wb, SH, gridLines = FALSE, tabColour = "#1F3864", zoom = 90)
lab_r <- paste0("SE ", sprintf("%02d", lubridate::epiweek(R_SHOW)), "\n", .dm(data_rodada[as.character(R_SHOW)]))
dem <- DEMAIS[DEMAIS$id %in% names(AC), ]
eq_extra <- setdiff(COLS_EQ, EQUIPE)
C1 <- data.frame(stringsAsFactors = FALSE,
                 nome = c("SE", "Nome", "Nº SINAN", "Início dos sintomas", "Etiologia", "Sorogrupo", "Critério de confirmação",
                          "Situação", "Pendência", "Desde a última semana epidemiológica", "Semanas seguidas na lista", COLS_EQ,
                          "Classificação", "Evolução", "Exames registrados", "Notificação", "Encerramento", "Dias desde a notificação",
                          "Idade", "Sexo", "Município de residência", "GVE", "DRS",
                          lab_r, "Na lista desde", "Semanas com pendência", "O que mudou (mais recente primeiro)", dem$rot, "chave"),
                 larg = c(8, 30, 10, 11, 24, 10, 15, 16, 44, 32, 10, 17, 16, 12, 34, rep(20, length(eq_extra)),
                          14, 15, 36, 11, 12, 10, 6, 5, 18, 16, 16, rep(12.5, length(R_SHOW)), 11, 10, 60,
                          ifelse(dem$tipo == "data", 11, ifelse(grepl("^Vacina|^BCG|^Outra vacina", dem$rot), 14, 16)), 12),
                 grupo = c("SEMANA", rep("FICHA", 3), rep("ETIOLOGIA", 3), rep("SITUAÇÃO NO ARGOS", 4),
                           rep("EQUIPE (o Argos não apaga)", length(COLS_EQ)), rep("O CASO NO SINAN", 11),
                           rep("HISTÓRICO NO ARGOS (situação a cada semana)", length(R_SHOW) + 3),
                           rep("DEMAIS DADOS DA FICHA (grupo recolhível)", nrow(dem)), " "),
                 wrap = c(FALSE, TRUE, FALSE, FALSE, TRUE, FALSE, TRUE, TRUE, TRUE, TRUE, FALSE, rep(TRUE, length(COLS_EQ)),
                          FALSE, TRUE, TRUE, FALSE, FALSE, FALSE, FALSE, FALSE, TRUE, TRUE, TRUE,
                          rep(TRUE, length(R_SHOW)), FALSE, FALSE, TRUE, dem$tipo != "data", FALSE),
                 tipo = c("cent", "neg", "cent", "data", "etio", "sorog", "crit", "sit", "cat", "desde", "cent", rep("eq", length(COLS_EQ)),
                          "classif", "evol", "", "data", "data", "cent", "cent", "cent", "", "", "",
                          rep("rod", length(R_SHOW)), "data", "cent", "cinza", ifelse(dem$tipo == "data", "data", ""), ""))
# a planilha é lida como texto: datas e números da equipe voltam ao tipo certo
.num_excel <- function(v) grepl("^-?\\d+([.,]\\d+)?$", v)
for (j in COLS_EQ) {
  v <- as.character(EQV[[j]]); ok <- !is.na(v) & nzchar(v)
  if (!any(ok)) next
  if (grepl("^Data", j)) {
    dv <- .data(v); serial <- ok & is.na(dv) & .num_excel(v)
    dv[serial] <- openxlsx::convertToDate(as.numeric(v[serial]))
    if (all(!ok | !is.na(dv))) EQV[[j]] <- dv
  } else if (!j %in% EQUIPE && all(.num_excel(v[ok]))) EQV[[j]] <- as.numeric(sub(",", ".", v))
}
D1 <- data.frame(AC$sem, .se_lab(AC$sem), AC$nome, AC$nu, AC$dt_sin, AC$etiologia, AC$sorogrupo, AC$criterio,
                 AC$sit, AC$cat_txt, AC$desde, ifelse(AC$seg > 0, AC$seg, NA),
                 EQV[, COLS_EQ, drop = FALSE],
                 AC$classif, AC$evolucao, AC$exames, AC$dt_not, AC$dt_enc,
                 AC$dias, AC$idade, AC$sexo, AC$muni, AC$gve, AC$drs,
                 as.data.frame(matrix(.rot_estado(CEL), ncol = length(R_SHOW)), stringsAsFactors = FALSE),
                 AC$na_lista, AC$n_rod, AC$mudou, AC[, dem$id, drop = FALSE], AC$chave,
                 stringsAsFactors = FALSE, check.names = FALSE)
names(D1) <- c(".sem", C1$nome)
RAWC <- as.data.frame(CEL, stringsAsFactors = FALSE)
blocos <- split(seq_len(nrow(D1)), factor(as.character(D1$.sem), levels = unique(as.character(D1$.sem))))
idx <- integer(); tipo <- character(); rot_sep <- character()
for (b in blocos) {
  s <- D1$.sem[b[1]]; sitb <- D1[["Situação"]][b]
  npen <- sum(!sitb %in% c("RESOLVIDA NESTA SEMANA", "RESOLVIDA", "SAIU DA BASE"))
  nalta <- sum(AC$pri[b] == "Alta", na.rm = TRUE); nres <- sum(grepl("^RESOLVIDA", sitb))
  rot_sep <- c(rot_sep, paste0("SEMANA EPIDEMIOLÓGICA ", sprintf("%02d", lubridate::epiweek(s)), "/", lubridate::epiyear(s),
                               "   ·   ", format(s, "%d/%m"), " a ", format(s + 6, "%d/%m/%Y"), "   ·   ",
                               npen, if (npen == 1) " pendente" else " pendentes",
                               if (nalta) paste0(" (", nalta, " de alta prioridade)") else "",
                               if (nres) paste0("   ·   ", nres, if (nres == 1) " resolvida" else " resolvidas") else ""))
  idx <- c(idx, NA, b); tipo <- c(tipo, "sep", rep("dado", length(b)))
}
T1 <- D1[ifelse(is.na(idx), 1L, idx), , drop = FALSE]; T1[is.na(idx), ] <- NA
T1$SE[is.na(idx)] <- rot_sep
R1 <- RAWC[ifelse(is.na(idx), 1L, idx), , drop = FALSE]; R1[is.na(idx), ] <- NA
CATC <- AC$cat_cor[ifelse(is.na(idx), 1L, idx)]; CATC[is.na(idx)] <- NA
# linhas acrescentadas à mão pela equipe vão para o fim, como estavam
if (!is.null(ED$extras)) {
  ext <- as.data.frame(lapply(T1[seq_len(nrow(ED$extras) + 1), , drop = FALSE], function(v) v[NA]), check.names = FALSE)
  ext$SE[1] <- "LINHAS ACRESCENTADAS PELA EQUIPE (o Argos não mexe nelas)"
  for (j in intersect(names(ED$extras), names(T1))) {
    v <- ED$extras[[j]]
    if (inherits(T1[[j]], "Date")) v <- if (all(is.na(v) | grepl("^\\d+$", v))) openxlsx::convertToDate(as.numeric(v)) else .data(v)
    else if (is.numeric(T1[[j]])) v <- suppressWarnings(as.numeric(v)) else v <- as.character(v)
    ext[[j]][-1] <- v
  }
  T1 <- rbind(T1, ext); tipo <- c(tipo, "sep_eq", rep("extra", nrow(ED$extras)))
  R1 <- rbind(R1, R1[rep(NA_integer_, nrow(ext)), , drop = FALSE]); CATC <- c(CATC, rep(NA, nrow(ext)))
}
T1$.sem <- NULL
L0 <- L_CAB + 1
nc <- ncol(T1)
.cabecalho(wb, SH, "acompanhamento semanal das fichas de meningite", 12)
n_pend <- sum(!AC$sit %in% c("RESOLVIDA NESTA SEMANA", "RESOLVIDA", "SAIU DA BASE"))
openxlsx::writeData(wb, SH, paste0(
  .n0(n_pend), " fichas pendentes (", sum(AC$pri == "Alta", na.rm = TRUE), " de alta prioridade)  ·  ",
  sum(AC$sit %in% c("NOVA", "VOLTOU")), " entraram nesta semana  ·  ",
  sum(AC$sit == "RESOLVIDA NESTA SEMANA"), " resolvidas nesta semana  ·  ",
  sum(AC$sit == "RESOLVIDA"), " resolvidas antes  ·  colunas amarelas (EQUIPE): o Argos guarda o que estiver nelas"),
  startRow = 3, startCol = 1)
openxlsx::addStyle(wb, SH, S_RES, rows = 3, cols = 1)
.grupos(wb, SH, C1$grupo)
openxlsx::writeData(wb, SH, T1, startRow = L_CAB, startCol = 1, colNames = TRUE)
j_eq <- match(COLS_EQ, C1$nome)
openxlsx::addStyle(wb, SH, S_CAB, rows = L_CAB, cols = setdiff(seq_len(nc), j_eq), gridExpand = TRUE)
openxlsx::addStyle(wb, SH, S_CAB_EQ, rows = L_CAB, cols = j_eq, gridExpand = TRUE)
lin <- L_CAB + seq_len(nrow(T1))
l_dad <- lin[tipo %in% c("dado", "extra")]; dd <- T1[tipo %in% c("dado", "extra"), , drop = FALSE]
openxlsx::addStyle(wb, SH, S_DADO, rows = l_dad, cols = seq_len(nc), gridExpand = TRUE)
sit_d <- dd[["Situação"]]
.pinta <- function(r, j, st) if (length(r) && length(j)) openxlsx::addStyle(wb, SH, st, rows = r, cols = j, gridExpand = TRUE, stack = TRUE)
.pinta(l_dad[grepl("^RESOLVIDA", sit_d)], seq_len(nc), S_RESOLV)
.pinta(l_dad[sit_d %in% "SAIU DA BASE"], seq_len(nc), S_FORA)
for (j in which(C1$wrap)) .pinta(l_dad, j, S_WRAP)
for (j in which(C1$tipo == "cent")) .pinta(l_dad, j, S_CENT)
for (j in which(C1$tipo == "data")) .pinta(l_dad, j, S_DATA)
.pinta(l_dad, which(C1$tipo == "neg"), S_NEG)
.pinta(l_dad, which(C1$tipo == "cinza"), .st(fontColour = "#595959"))
j_sit <- which(C1$tipo == "sit")
for (k in seq_len(nrow(SITUACOES))) .pinta(l_dad[sit_d %in% SITUACOES$sit[k]], j_sit, .cor(SITUACOES$fundo[k], SITUACOES$letra[k]))
j_cat <- which(C1$tipo == "cat"); catc_d <- CATC[tipo %in% c("dado", "extra")]
for (k in seq_len(nrow(TODOS_ESTADOS))) .pinta(l_dad[catc_d %in% TODOS_ESTADOS$cat[k]], j_cat,
                                               .cor(TODOS_ESTADOS$fundo[k], TODOS_ESTADOS$letra[k], centro = FALSE))
# etiologia, sorogrupo e critério: o que está em branco ou não especificado aparece em vermelho
for (tp in c("etio", "sorog", "crit")) {
  j <- which(C1$tipo == tp); v <- dd[[j]]
  .pinta(l_dad[grepl("em branco|não especificad|não determinad|não identificad|^Sem informação", v) & !grepl("^Asséptica", v)], j,
         .st(fontColour = "#C00000", textDecoration = "bold"))
}
.pinta(l_dad, which(C1$tipo == "sorog"), S_CENT)
.pinta(l_dad[grepl("^Óbito", dd[["Evolução"]])], which(C1$tipo == "evol"), .st(fontColour = "#C00000", textDecoration = "bold"))
.pinta(l_dad[dd[["Classificação"]] %in% "Em investigação"], which(C1$tipo == "classif"), .st(fontColour = "#1F4E79", textDecoration = "italic"))
j_des <- which(C1$tipo == "desde"); des <- dd[["Desde a última semana epidemiológica"]]; sem_l <- dd[["Semanas seguidas na lista"]]
.pinta(l_dad[grepl("^Segue", des) & sem_l %in% 4:999], j_des, .st(fontColour = "#C00000"))
.pinta(l_dad[grepl("^Segue", des) & !sem_l %in% 4:999], j_des, .st(fontColour = "#7F7F7F"))
.pinta(l_dad[grepl("→", des) & !grepl("^Segue", des)], j_des, .st(fontColour = "#2F5597", textDecoration = "bold"))
j_rod <- which(C1$tipo == "rod")
for (q in seq_along(j_rod)) for (k in seq_len(nrow(TODOS_ESTADOS))) {
  r <- lin[tipo == "dado" & R1[[q]] %in% TODOS_ESTADOS$cat[k]]
  .pinta(r, j_rod[q], .cor(TODOS_ESTADOS$fundo[k], TODOS_ESTADOS$letra[k]))
}
openxlsx::addStyle(wb, SH, S_EQUIPE, rows = l_dad, cols = j_eq, gridExpand = TRUE)
for (j in j_eq[vapply(EQV[, COLS_EQ, drop = FALSE], function(v) inherits(v, "Date"), logical(1))]) .pinta(l_dad, j, S_DATA)
openxlsx::addStyle(wb, SH, S_SEP, rows = lin[tipo == "sep"], cols = seq_len(nc), gridExpand = TRUE)
if (any(tipo == "sep_eq")) openxlsx::addStyle(wb, SH, S_SEP_EQ, rows = lin[tipo == "sep_eq"], cols = seq_len(nc), gridExpand = TRUE)
openxlsx::setColWidths(wb, SH, cols = seq_len(nc), widths = C1$larg)
openxlsx::setColWidths(wb, SH, cols = nc, widths = 12, hidden = TRUE)
j_dem <- which(C1$nome %in% dem$rot)
if (length(j_dem)) openxlsx::groupColumns(wb, SH, cols = j_dem, hidden = FALSE)
openxlsx::setRowHeights(wb, SH, rows = 4:5, heights = c(20, 44))
openxlsx::setRowHeights(wb, SH, rows = lin[grepl("^sep", tipo)], heights = 22)
openxlsx::setRowHeights(wb, SH, rows = l_dad, heights = .altura(dd, C1$larg, C1$wrap & C1$tipo != "rod"))
openxlsx::freezePane(wb, SH, firstActiveRow = L0, firstActiveCol = 5)
openxlsx::addFilter(wb, SH, rows = L_CAB, cols = seq_len(nc - 1))
openxlsx::addWorksheet(wb, "listas", visible = FALSE)
openxlsx::writeData(wb, "listas", c("Pendente", "Contato feito", "Aguardando retorno", "Corrigido no Sinan", "Sem retorno"),
                    colNames = FALSE)
if (length(l_dad))
  suppressWarnings(openxlsx::dataValidation(wb, SH, cols = j_eq[1], rows = min(l_dad):max(l_dad), type = "list",
                                            value = "'listas'!$A$1:$A$5"))
openxlsx::pageSetup(wb, SH, orientation = "landscape", printTitleRows = 4:5, paperSize = 9)  # sem fitToWidth: com tabColour corrompe o xlsx (openxlsx 4.2.5)

# ---------- ABA RESUMO
sh <- "Resumo"
openxlsx::addWorksheet(wb, sh, gridLines = FALSE, tabColour = "#BF8F00", zoom = 90)
.cabecalho(wb, sh, "resumo da semana", 3)
.bloco <- function(df, linha, titulo, col1 = 1) {
  openxlsx::writeData(wb, sh, titulo, startRow = linha, startCol = col1)
  openxlsx::addStyle(wb, sh, .st(fontSize = 12, textDecoration = "bold", fontColour = "#1F3864"), rows = linha, cols = col1)
  openxlsx::writeData(wb, sh, df, startRow = linha + 1, startCol = col1)
  openxlsx::addStyle(wb, sh, S_CAB, rows = linha + 1, cols = col1 - 1 + seq_len(ncol(df)), gridExpand = TRUE)
  if (nrow(df)) {
    openxlsx::addStyle(wb, sh, S_DADO, rows = linha + 1 + seq_len(nrow(df)), cols = col1 - 1 + seq_len(ncol(df)), gridExpand = TRUE)
    num <- which(vapply(df, is.numeric, logical(1)))
    if (length(num)) openxlsx::addStyle(wb, sh, S_CENT, rows = linha + 1 + seq_len(nrow(df)),
                                        cols = col1 - 1 + num, gridExpand = TRUE, stack = TRUE)
  }
  linha + 1 + nrow(df) + 2
}
PE <- AC[!AC$sit %in% c("RESOLVIDA NESTA SEMANA", "RESOLVIDA", "SAIU DA BASE"), ]
kpi <- data.frame(stringsAsFactors = FALSE,
                  Indicador = c("Fichas pendentes", "De alta prioridade", "Entraram nesta semana (novas ou que voltaram)",
                                "Resolvidas nesta semana", "Seguem pendentes há 4 semanas ou mais", "Resolvidas em semanas anteriores",
                                "Saíram da base do Sinan"),
                  Fichas = c(nrow(PE), sum(PE$pri == "Alta"), sum(AC$sit %in% c("NOVA", "VOLTOU")), sum(AC$sit == "RESOLVIDA NESTA SEMANA"),
                             sum(PE$seg >= 4), sum(AC$sit == "RESOLVIDA"), sum(AC$sit == "SAIU DA BASE")))
lr <- .bloco(kpi, 5, paste0("Rodada de ", format(d_atual, "%d/%m/%Y"),
                            if (!is.na(r_ant)) paste0(" (comparada com a de ", format(d_ant, "%d/%m/%Y"), ")") else ""))
ts <- setNames(data.frame(SITUACOES$sit, as.integer(table(factor(AC$sit, levels = SITUACOES$sit))),
                          stringsAsFactors = FALSE), c("Situação", "Fichas"))
l_sit <- lr + 2
lr <- .bloco(ts, lr, "Fichas por situação")
for (k in seq_len(nrow(SITUACOES)))
  openxlsx::addStyle(wb, sh, .cor(SITUACOES$fundo[k], SITUACOES$letra[k], centro = FALSE), rows = l_sit + k - 1, cols = 1, stack = TRUE)
tc <- as.data.frame.matrix(table(factor(PE$cat, levels = CATS$cat), factor(PE$pri, levels = names(PRIOR))))
tc <- data.frame(Categoria = CATS$cat, Total = rowSums(tc), tc, check.names = FALSE, stringsAsFactors = FALSE)
l_cat <- lr + 2
lr <- .bloco(tc, lr, "Fichas pendentes por categoria (a principal de cada ficha) e prioridade")
for (k in seq_len(nrow(CATS)))
  openxlsx::addStyle(wb, sh, .cor(CATS$fundo[k], CATS$letra[k], centro = FALSE), rows = l_cat + k - 1, cols = 1, stack = TRUE)
td <- as.data.frame.matrix(table(factor(ifelse(is.na(PE$drs), "(sem DRS)", PE$drs)), factor(PE$cat, levels = CATS$cat)))
names(td) <- CATS$curto
rn <- rownames(td)
td <- data.frame(DRS = rn, Pendentes = rowSums(td), td,
                 `Resolvidas nesta semana` = as.integer(table(factor(AC$drs[AC$sit == "RESOLVIDA NESTA SEMANA"], levels = rn))),
                 check.names = FALSE, stringsAsFactors = FALSE)
td <- td[order(-td$Pendentes), ]
l_drs <- lr + 1
lr <- .bloco(td, lr, "Fichas pendentes por DRS de residência")
for (k in seq_len(nrow(CATS)))
  openxlsx::addStyle(wb, sh, .cor(CATS$fundo[k], CATS$letra[k]), rows = l_drs, cols = 2 + k, stack = TRUE)
tr <- do.call(rbind, lapply(seq_along(rodadas), function(q) {
  h <- hist[hist$sem_rodada == rodadas[q], ]
  hp <- if (q > 1) hist[hist$sem_rodada == rodadas[q - 1], ] else NULL
  data.frame(`Semana (data da base do Sinan)` = format(data_rodada[as.character(rodadas[q])], "%d/%m/%Y"),
             SE = lubridate::epiweek(rodadas[q]), Pendentes = nrow(h), `Alta prioridade` = sum(h$pri == "Alta"),
             Entraram = if (is.null(hp)) NA else sum(!(h$chave %in% hp$chave)),
             Sairam = if (is.null(hp)) NA else sum(!(hp$chave %in% h$chave)),
             check.names = FALSE, stringsAsFactors = FALSE)
}))
names(tr)[names(tr) == "Sairam"] <- "Saíram"
lr <- .bloco(head(tr[nrow(tr):1, ], 30), lr, "Semanas do Argos (mais recente primeiro)")
openxlsx::setColWidths(wb, sh, cols = 1:12, widths = c(46, 11, 15, 14, 13, 13, 13, 13, 14, 14, 14, 16))

# ---------- ABA COMO LER
sh <- "Como ler"
openxlsx::addWorksheet(wb, sh, gridLines = FALSE, tabColour = "#7F7F7F", zoom = 90)
.cabecalho(wb, sh, "como ler esta planilha", 3)
leg <- data.frame(Categoria = CATS$cat, Prioridade = CATS$prioridade, `O que significa` = CATS$significa,
                  check.names = FALSE, stringsAsFactors = FALSE)
lr <- .bloco(leg, 5, "Categoria: o tipo de pendência (a cor é a mesma no histórico de cada ficha)")
for (k in seq_len(nrow(CATS)))
  openxlsx::addStyle(wb, sh, .cor(CATS$fundo[k], CATS$letra[k], centro = FALSE), rows = 6 + k, cols = 1, stack = TRUE)
openxlsx::addStyle(wb, sh, S_WRAP, rows = 6 + seq_len(nrow(CATS)), cols = 3, gridExpand = TRUE, stack = TRUE)
sl <- data.frame(Situacao = SITUACOES$sit, `O que significa` = SITUACOES$significa,
                 check.names = FALSE, stringsAsFactors = FALSE)
names(sl)[1] <- "Situação"
l_s <- lr + 2
lr <- .bloco(sl, lr, "Situação: como a ficha está em relação à semana epidemiológica anterior")
for (k in seq_len(nrow(SITUACOES)))
  openxlsx::addStyle(wb, sh, .cor(SITUACOES$fundo[k], SITUACOES$letra[k], centro = FALSE), rows = l_s + k - 1, cols = 1, stack = TRUE)
rotulos <- data.frame(stringsAsFactors = FALSE,
                      `Na planilha` = c("Não especificada", "(em branco)", "Outras bactérias: não determinada", "Outras bactérias: agente em branco",
                                        "Outra etiologia: agente em branco", "Asséptica: não identificado", "Sorogrupo (em branco)", "\u2014"),
                      `De onde vem` = c("Diagnóstico 06 da ficha: meningite não especificada",
                                        "Caso confirmado com o campo Diagnóstico vazio",
                                        "Diagnóstico 05 (outras bactérias) com a bactéria marcada como não determinada (código 81)",
                                        "Diagnóstico 05 (outras bactérias) com o campo da bactéria vazio",
                                        "Diagnóstico 08 (outra etiologia) com o campo do agente vazio",
                                        "Diagnóstico 07 (asséptica) com o vírus marcado como não identificado (código 75)",
                                        "Meningococo confirmado com o campo Sorogrupo vazio",
                                        "Não se aplica (ficha em investigação, descartada ou etiologia que não tem sorogrupo)"),
                      check.names = FALSE)
names(rotulos) <- c("Na planilha", "De onde vem")
lr <- .bloco(rotulos, lr, "Etiologia e sorogrupo: o que cada rótulo quer dizer (em vermelho = em branco ou não especificado)")
notas <- c(
  paste0("Janela: notificações com início dos sintomas ",
         if (is.na(ANOS)) "em qualquer ano" else if (ANOS == 1) paste0("em ", ANO_REF) else paste0("de ", ANO_REF - ANOS + 1, " a ", ANO_REF),
         " (escolha ANOS no início do argos.R; NA = todos os anos)."),
  paste0("Semana: semana epidemiológica de ", if (SEMANA_POR == "notificacao") "notificação" else "início dos sintomas",
         " (domingo a sábado), da mais recente para a mais antiga. Em cada semana vêm primeiro as pendentes, depois as resolvidas."),
  "A aba mostra toda ficha que tem ou já teve pendência. As resolvidas ficam em verde-claro, para registro.",
  "Uma linha por notificação (número + data de notificação). Se houver cópias, vale o registro mais recente e a ficha recebe a pendência DUPLICIDADE.",
  "A coluna Pendência lista tudo o que o Argos achou na ficha, da pendência mais grave para a mais leve; a cor é a da mais grave.",
  "Entram todas as meningites (qualquer etiologia) e todas as classificações: em investigação, confirmadas e descartadas que se contradizem.",
  "Meningococo: mesmas regras da auditoria do meningococo (v9). Sorogrupável = cultura, CIE, látex ou PCR; o código '0' nos exames conta como sem informação.",
  "Histórico no Argos: a situação da ficha em cada uma das últimas semanas (data da base do Sinan) e o que mudou em cada uma.",
  "O QUE O ARGOS GUARDA: o que estiver nas colunas amarelas (EQUIPE), colunas novas que a equipe criar nesta aba, linhas acrescentadas à mão (vão para o fim) e abas novas. Ele liga cada anotação à ficha pela coluna oculta 'chave'; ordenar e filtrar não atrapalha.",
  "O QUE O ARGOS REFAZ: todas as outras colunas, a partir do Sinan; o que for mudado nelas é substituído na semana seguinte.",
  "Se a planilha estiver aberta quando o Argos rodar, ele para sem mexer em nada. A versão anterior fica em backup/.",
  "A memória do Argos (situação das fichas a cada semana e cópia das anotações) fica em argos_historico.rds, na mesma pasta; é dela que vêm o histórico e a recuperação das anotações.",
  "Fonte: Sinan NET, exportação bd_meningite usada pela vigilância das meningites (CVE/SES-SP).")
openxlsx::writeData(wb, sh, "Regras", startRow = lr, startCol = 1)
openxlsx::addStyle(wb, sh, .st(fontSize = 12, textDecoration = "bold", fontColour = "#1F3864"), rows = lr, cols = 1)
openxlsx::writeData(wb, sh, data.frame(x = paste("•", notas)), startRow = lr + 1, startCol = 1, colNames = FALSE)
lr <- lr + length(notas) + 3
openxlsx::writeData(wb, sh, data.frame(x = c(
  "\"Centum luminibus cinctum caput Argus habebat; inde suis vicibus capiebant bina quietem,",
  "cetera servabant atque in statione manebant.\"",
  "(Argos tinha a cabeça cercada de cem olhos; deles, dois de cada vez descansavam, enquanto os outros vigiavam e permaneciam em seu posto.)",
  "Ovídio, Metamorfoses, Livro I, versos 625-627. Tradução livre.")), startRow = lr, startCol = 1, colNames = FALSE)
openxlsx::addStyle(wb, sh, .st(fontColour = "#595959", textDecoration = "italic"), rows = lr:(lr + 3), cols = 1, gridExpand = TRUE)
openxlsx::setColWidths(wb, sh, cols = 1:3, widths = c(36, 22, 110))

# ordem das abas: as do Argos primeiro, depois as da equipe; a lista suspensa fica oculta
ord <- c(match(c(SH, "Resumo", "Como ler"), names(wb)), match(abas_eq, names(wb)), match("listas", names(wb)))
openxlsx::worksheetOrder(wb) <- ord[!is.na(ord)]
openxlsx::activeSheet(wb) <- 1

## ---- 11. SALVAR -------------------------------------------------------------------
tmp <- file.path(PASTA, paste0("argos_gravando_", Sys.getpid(), ".xlsx"))
openxlsx::saveWorkbook(wb, tmp, overwrite = TRUE)
if (file.exists(ARQ_XLSX)) {
  dir.create(file.path(PASTA, "backup"), showWarnings = FALSE)
  invisible(file.copy(ARQ_XLSX, file.path(PASTA, "backup", sub("\\.xlsx$", "_anterior.xlsx", basename(ARQ_XLSX))), overwrite = TRUE))
}
ok <- suppressWarnings(file.rename(tmp, ARQ_XLSX))
if (!ok) { ok <- suppressWarnings(file.copy(tmp, ARQ_XLSX, overwrite = TRUE)); unlink(tmp) }
if (!ok) stop("Não consegui gravar a planilha (ela foi aberta durante a rodada?):\n  ", ARQ_XLSX,
              "\n  Feche-a e rode de novo. A versão anterior continua igual.", call. = FALSE)
if (file.exists(ARQ_HIST)) {
  dir.create(file.path(PASTA, "backup"), showWarnings = FALSE)
  invisible(file.copy(ARQ_HIST, file.path(PASTA, "backup", "argos_historico_anterior.rds"), overwrite = TRUE))
}
saveRDS(list(versao = "1.0", hist = hist, notas = notas_ant), ARQ_HIST)

.diga(strrep("-", 84))
.diga(">> ", .n0(nrow(PE)), " fichas pendentes (", sum(PE$pri == "Alta"), " de alta prioridade)")
tb <- table(factor(PE$cat, levels = CATS$cat))
for (k in names(tb)[tb > 0]) .diga("   ", formatC(k, width = -24), formatC(tb[[k]], width = 5))
.diga(">> Nesta semana: ", sum(AC$sit %in% c("NOVA", "VOLTOU")), " entraram, ",
      sum(AC$sit == "RESOLVIDA NESTA SEMANA"), " foram resolvidas, ", sum(AC$sit == "SEM MUDANÇA"), " seguem sem mudança")
.diga(">> Planilha: ", ARQ_XLSX)
if (ABRIR_EXCEL && .Platform$OS.type == "windows" && (interactive() || Sys.getenv("ARGOS_BAT") == "1"))
  try(shell.exec(ARQ_XLSX), silent = TRUE)