FROM nginx:latest
COPY index.html /usr/share/nginx/html/index.html
RUN apt-get update && apt-get -y install openssh-server netcat inetutils-ping net-tools

RUN mkdir /var/run/sshd
RUN echo 'root:password1' | chpasswd
RUN echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config

# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

# CMD /usr/sbin/sshd -D ; nginx -g "daemon off;"
CMD /etc/init.d/ssh start ; nginx -g "daemon off;"
