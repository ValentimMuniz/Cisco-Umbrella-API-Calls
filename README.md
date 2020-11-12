# Cisco Umbrella API Calls

Desenvolvido por: Valentim Uliana

Essa aplicação tem como intuito facilitar os cadastros em massa de Internal Domains, Internal Networks e Sites do Cisco Umbrella, pois faz o uso de arquivos CSV para envio! Porém em questão de Sites e Domains, há a opção de cadastrá-los manualmente. Alguns modelos de CSV estão nesse repositório.

# Funcionamento
1. Primeiramente você irá precisar das API Key e API Secret do <a href="https://docs.umbrella.com/umbrella-api/docs/authentication-and-errors">Cisco Umbrella Management API</a> para fazer as requisições da aplicação.
2. Você irá precisar também do Ubrella Organization ID! Use <a href = "https://docs.umbrella.com/deployment-umbrella/docs/find-your-organization-id" target="_blank">esta documentacao</a> para saber como obter seu Organization ID.
3. Para ter acesso a aplicação, o email do usuário precisará ter permissão de Full Admin à orgarnização especificada na configuração. Use <a href="https://docs.umbrella.com/deployment-umbrella/docs/add-a-new-user"> esta documentação</a> para saber como funcionam as permissões de usuários no Umbrella.
4. O CSV deve ser em formato serparado por vírgula!!<br>
5. O CSV de Internal Networks deve ser preenchido da seguinte forma:<br>
   <b>Nome,IP,Prefixo</b>
6. Pasta raiz da aplicação fica em C:/uses/USERNAME/.umbrella_api_calls <b>(IMPORTANTE)</b>
7. Todos os logs gerados estão na pasta logs da pasta raiz da aplicação.
8. O arquivo de configuração vai ser gerado na pasta raiz da aplicação.

# Features
A aplicação vai trabalhar de modo inteligente fazendo todas as verificações e logando tudo para a pasta de logs da raiz da aplicação! Entre as verificações estão:
1. Se o CSV de Internal Networks foi preenchido corretamente, como citado <b>acima</b> a aplicação vai te informar que está incorreto, não permite o cadastro, e vai gerar um arquivo de log informando a linha do CSV que está incorreta!
2. No cadastro de Internal Networks, a aplicação é capaz de fazer a verificação se um Ip/Prefixo está correto, se estiver incorreto um arquivo de log é gerado informando quais Ip's que não foram preenchidos corretamente. Lembrando que precisa ser um IP de rede para cadastro no Umbrella.
3. A aplicação vai retornar mensagens em todos os casos, desde de, erros de configuração até quando tudo ocorreu bem e foram feitas as requisições!
4. Toda requisição sucedida, irá gerar um log para o que foi cadastrado no umbrella
5. Em todos os tipo de cadastros, sendo eles: Site, Internal Networks ou Internal Domains, a alicação verifica o que já está cadastrado no umbrella e compara com o CSV, depois ignora tudo o que já está cadastrado e assim só cadastrado o que realmente é novo!
6. Todos os arquivos de logs dão a informação de horário em que a requisição foi feita! São eles :<br>
   <b>wrongips.log</b> - Arquivo de log dos Ip's que estão errados no CSV de Internal Networks.<br>
   <b>wrongCSV.log</b> - Arquivo de log que informa as linhas que estão erradas no CSV de Internal Networks(lenbrando que o correto está no <b>item 5</b> do funcionamento).<br>
   <b>registred_internalNetworks.log</b> - Arquivo de log que informa as Internal Networks do CSV selecionado que foram cadastradas.<br>
   <b>registred_domains.log</b> - Arquivo de log que informa os Internal Domains do CSV selecionado que foram cadastradas.<br>
   <b>registred_sites.log</b> - Arquivo de log que informa os Sites do CSV selecionado que foram cadastradas.
<br><br><br>
<img src="images/aplicacao.png">

