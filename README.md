# Cisco Umbrella API Calls

Desenvolvido por: Valentim Uliana

Essa aplicação tem como intuito facilitar os cadastros em massa de Internal Domains, Internal Networks,Sites e Destinations do Cisco Umbrella, pois faz o uso de arquivos CSV para envio! Porém em questão de Sites,Domains e Destinations, há a opção de cadastrá-los manualmente. Alguns modelos de CSV estão nesse repositório.

# Funcionamento
1. Primeiramente você irá precisar das API Key e API Secret do <a href="https://docs.umbrella.com/umbrella-api/docs/authentication-and-errors">Cisco Umbrella Management API</a> para fazer as requisições da aplicação.
2. Você também irá precisar das API key e API Secret do <a href="https://developer.cisco.com/docs/cloud-security/#!reporting-v2-getting-started/authentication"> Cisco Umbrella Reporting API</a>
3. Você também irá precisar de uma chave de API do <a href="https://developer.cisco.com/docs/cloud-security/#!investigate-getting-started/authentication"> Cisco Umbrella Investigate API</a>
4. Você irá precisar também do Umbrella Organization ID! Use <a href = "https://docs.umbrella.com/deployment-umbrella/docs/find-your-organization-id" target="_blank">esta documentacao</a> para saber como obter seu Organization ID.
5. Para ter acesso a aplicação, o email do usuário precisará ter permissão de Full Admin à orgarnização especificada na configuração. Use <a href="https://docs.umbrella.com/deployment-umbrella/docs/add-a-new-user"> esta documentação</a> para saber como funcionam as permissões de usuários no Umbrella.
6. O CSV deve ser em formato serparado por vírgula!!<br>
7. O CSV de Internal Networks deve ser preenchido da seguinte forma:<br>
   <b>Nome,IP,Prefixo</b>
6. Pasta raiz da aplicação fica em C:/uses/USERNAME/.umbrella_api_calls <b>(IMPORTANTE)</b>
7. Todos os logs gerados estão na pasta <b>logs</b> da pasta raiz da aplicação.
8. Todos os reports gerados estão na pasta <b>reports</b> da pasta raiz da aplicação.
9. O arquivo de configuração vai ser gerado na pasta raiz da aplicação.
10. A aplicação tem duas traduções nativas: Inglês e Português, fica a disposição do usuário qual utilizar

# Features
A aplicação vai trabalhar de modo inteligente fazendo todas as verificações e logando tudo para a pasta de logs da raiz da aplicação! Entre as verificações estão:
1. Se o CSV de Internal Networks foi preenchido corretamente, como citado <b>acima</b> a aplicação vai te informar que está incorreto, não permite o cadastro, e vai gerar um arquivo de log informando a linha do CSV que está incorreta! E também informa qualquer outro CSV que esteja incorreto.
2. No cadastro de Internal Networks, a aplicação é capaz de fazer a verificação se um Ip/Prefixo está correto, se estiver incorreto um arquivo de log é gerado informando quais Ip's que não foram preenchidos corretamente. Lembrando que precisa ser um IP de rede para cadastro no Umbrella.
3. A aplicação vai retornar mensagens em todos os casos, desde de, erros de configuração até quando tudo ocorreu bem e foram feitas as requisições!
4. Toda requisição sucedida, irá gerar um log para o que foi cadastrado no umbrella!
5. Em todos os tipo de cadastros, sendo eles: Site, Internal Networks, Internal Domains ou Destinations a aplicação verifica o que já está cadastrado no umbrella e compara com o CSV, depois ignora tudo o que já está cadastrado e assim só cadastrado o que realmente é novo!
6. Todos os arquivos de logs dão a informação de horário em que a requisição foi feita! São eles :<br>
   <b>wrongips.log</b> - Arquivo de log dos Ip's que estão errados no CSV de Internal Networks.<br>
   <b>wrongCSV.log</b> - Arquivo de log que informa as linhas que estão erradas no CSV de Internal Networks(lenbrando que o correto está no <b>item 5</b> do funcionamento), e também informa as linhas erradas em CSV de Internal Domains e Sites.<br>
   <b>registred_internalNetworks.log</b> - Arquivo de log que informa as Internal Networks do CSV selecionado que foram cadastradas.<br>
   <b>registred_domains.log</b> - Arquivo de log que informa os Internal Domains do CSV selecionado que foram cadastradas.<br>
   <b>registred_sites.log</b> - Arquivo de log que informa os Sites do CSV selecionado que foram cadastradas.
   <b>registred_destinations.log</b> - Arquivo de log que informa os Destinos do CSV selecionado que foram cadastradas.
<br><br><br>
<img src="images/access.png"><br><br>
<img src="images/menu.png"><br><br><br>

# Investigate
A aplicaçã é capaz de ver a reputação de um Domínio/IP através do Umbrella Investigate, e com isso você conseguirá adicionar esse Domínio/IP em algum Destination list se a disposição for maliciosa.
<br><br><br>
# Reporting
A aplicação é capaz de rodar um reporting do Cisco Umbrella entre duas datas e o resultado do report será um arquivo <b>.csv</b><br>
Pontos de atenção:
1. O reporting é feito de hora em hora através de duas datas, com isso consegue trazer mais resultados por tempo indeterminado
2. O limite de cada request é de <b>5000</b>, ou seja, se nessa uma hora de reporting tiver mais que 5000 requisições do Umbrella, ele só vai pegar as 5000 primeiras.
