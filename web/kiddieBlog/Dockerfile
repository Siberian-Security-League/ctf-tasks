FROM httpd:2.4.49
COPY ./app/httpd.conf /usr/local/apache2/conf/httpd.conf
COPY ./app/site/ /var/www/
RUN mkdir /easterEgg/
COPY ./app/flag.txt /easterEgg/
EXPOSE 8081