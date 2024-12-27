1. To run the benchmarks at your machine (with Ubuntu 20.04 LTS), first install all dependencies as follows:
    ```
    sudo apt-get update
    sudo apt-get -y install make bison flex libgmp-dev libmpc-dev python3 python3-dev python3-pip libssl-dev
    
    wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
    tar -xvf pbc-0.5.14.tar.gz
    cd pbc-0.5.14
    sudo ./configure
    sudo make
    sudo make install
    cd ..
    
    sudo ldconfig /usr/local/lib
    
    cat <<EOF >/home/ubuntu/.profile
    export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
    EOF
    
    source /home/ubuntu/.profile
    export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib
    export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
     
    git clone https://github.com/JHUISI/charm.git
    cd charm
    sudo ./configure.sh
    sudo make
    sudo make install
    sudo make test
    cd ..
    
    python3 -m pip install --upgrade pip
    sudo pip3 install gevent setuptools gevent numpy ecdsa pysocks gmpy2 zfec gipc pycrypto coincurve
    
    sudo apt-get install libleveldb-dev
    pip3 install plyvel
    sudo apt-get install g++
    sudo apt-get install build-essential
    pip install leveldb

    git clone https://github.com/sagrawal87/ABE
    cd ABE/
    make && pip install . && python3 samples/main.py
    cd ..
   ```

2. Run Consensus 1000 data, each copy of a single round of consensus proposed 10 data
   ```
   New terminal
       ./run_local_network_test.sh 4 1 10 1000
   
   New terminal
       cd blockchain_server
       python3 main_chain.py
   
   New terminal
       cd temp_db
       python3 main_db.py
   
   New terminal
       cd user_client
       python3 write_send.py
       python3 inquire_chain.py
   ```
Note: The SGX-related code was not included in the repository, mainly due to deployment considerations. The code comparing on-chain and off-chain components was also not included, as the time for revising the paper was quite tight. 
To use fabric on-chain, you need to write it yourself.
In order to facilitate the experiment, the code writing is not very standardized, and the standardized code will be uploaded later.
