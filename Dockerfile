FROM armhf/alpine

RUN apk --update --upgrade add curl git 
RUN apk --update --upgrade add ruby ruby-bundler
RUN rm -rf /var/cache/apk/*

CMD ["sh"]