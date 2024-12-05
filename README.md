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

3. If you would like to test the code among AWS cloud servers (with Ubuntu 20.04 LTS). You can follow the commands inside run_local_network_test.sh to remotely start the protocols at all servers. An example to conduct the WAN tests from your PC side terminal can be:
   ```
   # the number of remove AWS servers
   N = 4
   
   # public IPs --- This is the public IPs of AWS servers
    pubIPsVar=([0]='3.236.98.149'
    [1]='3.250.230.5'
    [2]='13.236.193.178'
    [3]='18.181.208.49')
    
   # private IPs --- This is the private IPs of AWS servers
    priIPsVar=([0]='172.31.71.134'
    [1]='172.31.7.198'
    [2]='172.31.6.250'
    [3]='172.31.2.176')
   
   # Clone code to all remote AWS servers from github
    i=0; while [ $i -le $(( N-1 )) ]; do
    ssh -i "/home/your-name/your-key-dir/your-sk.pem" -o StrictHostKeyChecking=no ubuntu@${pubIPsVar[i]} "git clone --branch master https://github.com/yylluu/dumbo.git" &
    i=$(( i+1 ))
    done
   
   # Update IP addresses to all remote AWS servers 
    rm tmp_hosts.config
    i=0; while [ $i -le $(( N-1 )) ]; do
      echo $i ${priIPsVar[$i]} ${pubIPsVar[$i]} $(( $((200 * $i)) + 10000 )) >> tmp_hosts.config
      i=$(( i+1 ))
    done
    i=0; while [ $i -le $(( N-1 )) ]; do
      ssh -o "StrictHostKeyChecking no" -i "/home/your-name/your-key-dir/your-sk.pem" ubuntu@${pubIPsVar[i]} "rm /home/ubuntu/dumbo/hosts.config"
      scp -i "/home/your-name/your-key-dir/your-sk.pem" tmp_hosts.config ubuntu@${pubIPsVar[i]}:/home/ubuntu/dumbo/hosts.config &
      i=$(( i+1 ))
    done
    
    # Start Protocols at all remote AWS servers
    i=0; while [ $i -le $(( N-1 )) ]; do   ssh -i "/home/your-name/your-key-dir/your-sk.pem" ubuntu@${pubIPsVar[i]} "export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib; export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib; cd dumbo; nohup python3 run_socket_node.py --sid 'sidA' --id $i --N $N --f $(( (N-1)/3 )) --B 10000 --K 11 --S 50 --T 2 --P "bdt" --F 1000000 > node-$i.out" &   i=$(( i+1 )); done
 
    # Download logs from all remote AWS servers to your local PC
    i=0
    while [ $i -le $(( N-1 )) ]
    do
      scp -i "/home/your-name/your-key-dir/your-sk.pem" ubuntu@${pubIPsVar[i]}:/home/ubuntu/dumbo/log/node-$i.log node-$i.log &
      i=$(( i+1 ))
    done
 
   ```
Note: The SGX-related code was not included in the repository, mainly due to deployment considerations. The code comparing on-chain and off-chain components was also not included, as the time for revising the paper was quite tight. 
