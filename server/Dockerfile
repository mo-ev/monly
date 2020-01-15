FROM ubuntu:18.04

RUN useradd -ms /bin/bash monly

# support multiarch: i386 architecture
# install Java
# install essential tools
# install Nodejs
RUN dpkg --add-architecture i386 && \
    apt-get update -y && \
    apt-get install -y libncurses5:i386 libc6:i386 libstdc++6:i386 lib32gcc1 lib32ncurses5 lib32z1 zlib1g:i386 && \
    apt-get install -y --no-install-recommends openjdk-8-jdk && \
    apt-get install -y git wget zip curl autotools-dev automake && \
	apt-get install -y usbutils python3 python3-dev python3-pip gcc-multilib

RUN	curl -sL https://deb.nodesource.com/setup_12.x  | bash -
RUN curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add - && \
    echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list
RUN apt-get update -y && \
	apt-get install -y nodejs && \
	nodejs -v && apt-get install yarn && \
	npm -v
