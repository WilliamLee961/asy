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
<span style="color:red;">Note:</span> The SGX-related experiments are not included in this repository because the logic is relatively simple, focusing only on verification within the SGX environment. You will need to deploy and implement the SGX part yourself. During the paper revision phase, the reviewers suggested adding a comparison with other protocols, but due to time constraints, the related code has not yet been organized or uploaded. For this, please refer to the paper's discussion on homomorphic encryption and IPFS integration to understand the required implementation details. The on-chain logic is implemented using the Fabric platform, which requires multi-threaded read and write operations while receiving messages from the off-chain components. You will need to write the code for this part yourself. Additionally, some parts of the current code version still require optimization. Future updates with improved and standardized code will be provided based on the team's schedule.
