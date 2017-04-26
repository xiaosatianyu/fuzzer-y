#coding=utf-8
import angr
import logging
import os
import shellphish_afl
import shutil
import signal
import subprocess
import sys
import time


l = logging.getLogger("fuzzer.fuzzer")

config = { } #这个是干嘛的

class InstallError(Exception):
    pass

class Fuzzer(object):
    ''' Fuzzer object, spins up a fuzzing job on a binary '''

    def __init__(self, binary_path, work_dir, afl_count=1, library_path=None, time_limit=None,
            target_opts=None, extra_opts=None, create_dictionary=False,
            seeds=None, crash_mode=False, never_resume=False, qemu=True):
        '''
        :param binary_path: path to the binary to fuzz. List or tuple for multi-CB.
        :param work_dir: the work directory which contains fuzzing jobs, our job directory will go here
        :param afl_count: number of AFL jobs total to spin up for the binary
        :param library_path: library path to use, if none is specified a default is chosen
        :param timelimit: amount of time to fuzz for, has no effect besides returning True when calling timed_out
        :param seeds: list of inputs to seed fuzzing with
        :param target_opts: extra options to pass to the target
        :param extra_opts: extra options to pass to AFL when starting up
        :param crash_mode: if set to True AFL is set to crash explorer mode, and seed will be expected to be a crashing input
        :param never_resume: never resume an old fuzzing run, even if it's possible
        :param qemu: Utilize QEMU for instrumentation of binary.
        '''

        self.binary_path    = binary_path
        self.work_dir       = work_dir
        self.afl_count      = afl_count  #afl的数量
        self.time_limit     = time_limit #默认没有设置fuzz结束时间
        self.library_path   = library_path # 库路径, 什么用?
        self.target_opts    = [ ] if target_opts is None else target_opts
        self.crash_mode     = crash_mode
        self.qemu           = qemu

        Fuzzer._perform_env_checks() #系统环境配置

        if isinstance(binary_path,basestring): #basestring 是 str和unicode的抽象基类
            self.is_multicb = False
            self.binary_id = os.path.basename(binary_path) #程序名称
        elif isinstance(binary_path,(list,tuple)): #路径名称时list或者tuple时,是cgc,这个是怎么回事
            self.is_multicb = True
            self.binary_id = os.path.basename(binary_path[0])
        else:
            raise ValueError("Was expecting either a string or a list/tuple for binary_path! It's {} instead.".format(type(binary_path)))

        # sanity check crash mode
        if self.crash_mode:
            if seeds is None:
                raise ValueError("Seeds must be specified if using the fuzzer in crash mode")
            l.info("AFL will be started in crash mode")

        #self.seeds          = ["fuzz"] if seeds is None or len(seeds) == 0 else seeds
        ##modified by yyy
        self.seeds          = ['/home/xiaosatianyu/Desktop/driller/seed'] if seeds is None or len(seeds) == 0 else seeds
        
        self.job_dir  = os.path.join(self.work_dir, self.binary_id) #设定目标程序的工作目录
        self.in_dir   = os.path.join(self.job_dir, "input") #afl的输入目录
        self.out_dir  = os.path.join(self.job_dir, "sync") #afl的输出目录

        # sanity check extra opts
        self.extra_opts = extra_opts
        if self.extra_opts is not None:
            if not isinstance(self.extra_opts, list):
                raise ValueError("extra_opts must be a list of command line arguments")

        # base of the fuzzer package
        self.base = Fuzzer._get_base() #指向Fuzzer目录,下级必须带有bin目录

        self.start_time       = int(time.time())
        # create_dict script #创建字典
        self.create_dict_path = os.path.join(self.base, "bin", "create_dict.py") #这是一个创建字典的脚本
        # afl dictionary
        self.dictionary       = None
        # processes spun up
        self.procs            = [ ]  #添加启动的子进程对象
        # start the fuzzer ids at 0
        self.fuzz_id          = 0
        
        ##add by yyy---------------------------------------remove the afl cache for debug
        if os.path.isdir(self.work_dir):
            shutil.rmtree(self.work_dir) #删除工作目录, 此时尚未生成相关的目录,所以先删除一下没事
        ##end------------------------------------------
                
        # test if we're resuming an old run  #判断标准是是否存在afl的输出文件
        self.resuming         = bool(os.listdir(self.out_dir)) if os.path.isdir(self.out_dir) else False
        # has the fuzzer been turned on?
        self._on = False  

        if never_resume and self.resuming:
            l.info("could resume, but starting over upon request")
            shutil.rmtree(self.job_dir)
            self.resuming = False

        if self.is_multicb:  #这里针对cgc的一些改进
            # Where cgc/setup's Dockerfile checks it out
            # NOTE: 'afl/fakeforksrv' serves as 'qemu', as far as AFL is concerned
            #       Will actually invoke 'fakeforksrv/multicb-qemu'
            #       This QEMU cannot run standalone (always speaks the forkserver "protocol"),
            #       but 'fakeforksrv/run_via_fakeforksrv' allows it.
            # XXX: There is no driller/angr support, and probably will never be.
            self.afl_path = shellphish_afl.afl_bin('multi-cgc')
            self.afl_path_var = shellphish_afl.afl_path_var('multi-cgc')
        else:

            p = angr.Project(binary_path)
            # Loader 类
            self.os = p.loader.main_bin.os #查看是什么系统的文件, 通过angr的静态分析功能

            self.afl_dir          = shellphish_afl.afl_dir(self.os) #根据对应的执行程序 选择对应的afl; 一般的是选择unix

            # the path to AFL capable of calling driller
            self.afl_path         = shellphish_afl.afl_bin(self.os)# 读取aflfuzz执行程序
            #选择对应平台的qemu执行程序
            if self.os == 'cgc':
                self.afl_path_var = shellphish_afl.afl_path_var('cgc')
            else:
                self.afl_path_var = shellphish_afl.afl_path_var(p.arch.qemu_name) #选择对应的qemu
                # set up libraries
                self._export_library_path(p)

        self.qemu_dir         = self.afl_path_var # qemu的执行程序路径
        l.debug("self.start_time: %r", self.start_time)
        l.debug("self.afl_path: %s", self.afl_path)
        l.debug("self.afl_path_var: %s", self.afl_path_var)
        l.debug("self.qemu_dir: %s", self.qemu_dir)
        l.debug("self.binary_id: %s", self.binary_id)
        l.debug("self.work_dir: %s", self.work_dir)
        l.debug("self.resuming: %s", self.resuming)

        # if we're resuming an old run set the input_directory to a '-'
        if self.resuming:
            l.info("[%s] resuming old fuzzing run", self.binary_id)
            self.in_dir = "-"

        else:
            # create the work directory and input directory
            try:
                os.makedirs(self.in_dir)
            except OSError:
                l.warning("unable to create in_dir \"%s\"", self.in_dir)

            # populate the input directory
            self._initialize_seeds() #初始化复制测试用例

        # look for a dictionary
        dictionary_file = os.path.join(self.job_dir, "%s.dict" % self.binary_id)
        if os.path.isfile(dictionary_file):
            self.dictionary = dictionary_file

        # if a dictionary doesn't exist and we aren't resuming a run, create a dict
        elif not self.resuming:
            # call out to another process to create the dictionary so we can
            # limit it's memory
            if create_dictionary:
                if self._create_dict(dictionary_file):
                    self.dictionary = dictionary_file  #执行Fuzzer模块下的字典创建脚本
                else:
                    # no luck creating a dictionary
                    l.warning("[%s] unable to create dictionary", self.binary_id)

        # set environment variable for the AFL_PATH
        os.environ['AFL_PATH'] = self.afl_path_var  #设定afl对应的qemu到 环境变量中

    ### EXPOSED 这个函数是外放的, 调用一个内部的函数 启动afl
    def start(self):
        '''
        start fuzzing
        '''

        # spin up the AFL workers
        self._start_afl() #启动afl, 可以多个

        self._on = True

    @property
    def alive(self): #
        if not self._on or not len(self.stats):
            return False

        alive_cnt = 0
        if self._on:
            for fuzzer in self.stats:
                try:
                    os.kill(int(self.stats[fuzzer]['fuzzer_pid']), 0)
                    alive_cnt += 1
                except OSError, KeyError:
                    pass

        return bool(alive_cnt)

    def kill(self):
        for p in self.procs:
            p.terminate()
            p.wait()

        self._on = False

    @property
    def stats(self):  #读取fuzzer_stats文件

        # collect stats into dictionary
        stats = {}
        if os.path.isdir(self.out_dir):
            for fuzzer_dir in os.listdir(self.out_dir):
                stat_path = os.path.join(self.out_dir, fuzzer_dir, "fuzzer_stats")
                if os.path.isfile(stat_path):
                    stats[fuzzer_dir] = {}

                    with open(stat_path, "rb") as f:
                        stat_blob = f.read()
                        stat_lines = stat_blob.split("\n")[:-1]
                        for stat in stat_lines:
                            key, val = stat.split(":")
                            stats[fuzzer_dir][key.strip()] = val.strip()

        return stats

    def found_crash(self): #返回是否发现crash,这是由谁发现的crash

        return len(self.crashes()) > 0

    def add_fuzzer(self):
        '''
        add one fuzzer
        '''

        self.procs.append(self._start_afl_instance())

    def add_extension(self, name):
        """
        Spawn the mutation extension `name`
        :param name: name of extension
        :returns: True if able to spawn extension
        """

        extension_path = os.path.join(os.path.dirname(__file__), "..", "fuzzer", "extensions", "%s.py" % name)
        rpath = os.path.realpath(extension_path)

        l.debug("Attempting to spin up extension %s", rpath)

        if os.path.exists(extension_path):
            args = [sys.executable, extension_path, self.binary_path, self.out_dir]

            outfile_leaf = "%s-%d.log" % (name, len(self.procs))
            outfile = os.path.join(self.job_dir, outfile_leaf)
            with open(outfile, "wb") as fp:
                p = subprocess.Popen(args, stderr=fp)
            self.procs.append(p)
            return True

        return False

    def add_fuzzers(self, n):
        for _ in range(n):
            self.add_fuzzer()

    def remove_fuzzer(self):
        '''
        remove one fuzzer
        '''

        try:
            f = self.procs.pop()
        except IndexError:
            l.error("no fuzzer to remove")
            raise ValueError("no fuzzer to remove")

        f.kill()

    def remove_fuzzers(self, n):
        '''
        remove multiple fuzzers
        '''

        if n > len(self.procs):
            l.error("not more than %u fuzzers to remove", n)
            raise ValueError("not more than %u fuzzers to remove" % n)

        if n == len(self.procs):
            l.warning("removing all fuzzers")

        for _ in range(n):
            self.remove_fuzzer()

    def _get_crashing_inputs(self, signals):
        """
        Retrieve the crashes discovered by AFL. Only return those crashes which
        recieved a signal within 'signals' as the kill signal.

        :param signals: list of valid kill signal numbers
        :return: a list of strings which are crashing inputs
        """

        crashes = set()
        for fuzzer in os.listdir(self.out_dir):
            crashes_dir = os.path.join(self.out_dir, fuzzer, "crashes")

            if not os.path.isdir(crashes_dir):
                # if this entry doesn't have a crashes directory, just skip it
                continue

            for crash in os.listdir(crashes_dir):
                if crash == "README.txt":
                    # skip the readme entry
                    continue

                attrs = dict(map(lambda x: (x[0], x[-1]), map(lambda y: y.split(":"), crash.split(","))))

                if int(attrs['sig']) not in signals:
                    continue

                crash_path = os.path.join(crashes_dir, crash)
                with open(crash_path, 'rb') as f:
                    crashes.add(f.read())

        return list(crashes)

    def crashes(self):
        """
        Retrieve the crashes discovered by AFL. Since we are now detecting flag
        page leaks (via SIGUSR1) we will not return these leaks as crashes.
        Instead, these 'crashes' can be found with the leaks function.
        :return: a list of strings which are crashing inputs
        """

        return self._get_crashing_inputs([signal.SIGSEGV, signal.SIGILL])

    def queue(self, fuzzer='fuzzer-master'): #得到queue下的测试用例
        '''
        retrieve the current queue of inputs from a fuzzer
        :return: a list of strings which represent a fuzzer's queue
        '''

        if not fuzzer in os.listdir(self.out_dir):
            raise ValueError("fuzzer '%s' does not exist" % fuzzer)

        queue_path = os.path.join(self.out_dir, fuzzer, 'queue')
        queue_files = filter(lambda x: x != ".state", os.listdir(queue_path))

        queue_l = [ ]
        for q in queue_files:
            with open(os.path.join(queue_path, q), 'rb') as f:
                queue_l.append(f.read())

        return queue_l

    def bitmap(self, fuzzer='fuzzer-master'):
        '''
        retrieve the bitmap for the fuzzer `fuzzer`.
        :return: a string containing the contents of the bitmap.
        '''

        if not fuzzer in os.listdir(self.out_dir):
            raise ValueError("fuzzer '%s' does not exist" % fuzzer)

        bitmap_path = os.path.join(self.out_dir, fuzzer, "fuzz_bitmap")

        bdata = None
        try:
            with open(bitmap_path, "rb") as f:
                bdata = f.read()
        except IOError:
            pass

        return bdata

    def timed_out(self): 
        if self.time_limit is None:
            return False #默认是false
        return time.time() - self.start_time > self.time_limit

    def pollenate(self, testcases): #这里可能是利用新的测试用例的函数
        '''
        pollenate a fuzzing job with new testcases

        :param testcases: list of strings representing new inputs to introduce
        '''

        nectary_queue_directory = os.path.join(self.out_dir, 'pollen', 'queue')
        if not 'pollen' in os.listdir(self.out_dir):
            os.makedirs(nectary_queue_directory)

        pollen_cnt = len(os.listdir(nectary_queue_directory))

        for tcase in testcases:
            with open(os.path.join(nectary_queue_directory, "id:%06d,src:pollenation" % pollen_cnt), "w") as f:
                f.write(tcase)

            pollen_cnt += 1

    ### FUZZ PREP

    ##annotation by yyy------------------------------
    def _initialize_seeds(self):  # 将初始化的测试用例保存到input目录下
        '''
        populate the input directory with the seeds specified
        '''
 
        assert len(self.seeds) > 0, "Must specify at least one seed to start fuzzing with"
 
        l.debug("initializing seeds %r", self.seeds)
 
        template = os.path.join(self.in_dir, "seed-%d")
        for i, seed in enumerate(self.seeds):
            with open(template % i, "wb") as f:
                f.write(seed)
    ##end--------------------------------------------------------

    ##add by yyy-------------------------------------------
#     def _initialize_seeds(self):  # self.seeds指定的时测试用的目录
#         '''
#         populate the input directory with the seeds specified
#         '''
# 
#         assert len(self.seeds) > 0
# 
#         l.debug("initializing seeds %r", self.seeds)
#         
#         for seed in os.listdir(self.seeds):  # 遍历多个目标程序, 这里是程序名称
#            # 复制seed到input目录
#             shutil.copy(os.path.join(self.seeds, seed) , self.in_dir)
#            
           
    #end ---------------------------------------------
                


    ### DICTIONARY CREATION
    def _create_dict(self, dict_file):

        l.debug("creating a dictionary of string references within binary \"%s\"",
                self.binary_id)

        args = [self.create_dict_path]
        args += self.binary_path if self.is_multicb else [self.binary_path]

        with open(dict_file, "wb") as dfp:
            p = subprocess.Popen(args, stdout=dfp)
            retcode = p.wait()

        return retcode == 0 and os.path.getsize(dict_file)

    ### AFL SPAWNERS AFL生成器

    def _start_afl_instance(self, memory="8G"): #内存

        args = [self.afl_path] #aflfuzz的路径

        args += ["-i", self.in_dir]
        args += ["-o", self.out_dir]
        args += ["-m", memory]

        if self.qemu:
            args += ["-Q"]

        if self.crash_mode:
            args += ["-C"]

        if self.fuzz_id == 0:
            args += ["-M", "fuzzer-master"]
            outfile = "fuzzer-master.log"
        else:
            args += ["-S", "fuzzer-%d" % self.fuzz_id]  #启动多个afl
            outfile = "fuzzer-%d.log" % self.fuzz_id

        if self.dictionary is not None:
            args += ["-x", self.dictionary]

        if self.extra_opts is not None:
            args += self.extra_opts

        # auto-calculate timeout based on the number of binaries
        if self.is_multicb:
            args += ["-t", "%d+" % (1000 * len(self.binary_path))] #如果是cgc 就要加这个

        args += ["--"]
        args += self.binary_path if self.is_multicb else [self.binary_path]
        
        ##add by yyy-------------------------------------
        #args+=["@@", "/tmp/shelfish"]
        args+=["@@"]
        ##end-----------------------------------------------------
        
        args.extend(self.target_opts)

        l.debug("execing: %s > %s", ' '.join(args), outfile) #执行信息的输出

        # increment the fuzzer ID
        self.fuzz_id += 1

        outfile = os.path.join(self.job_dir, outfile)
        with open(outfile, "w") as fp:
            return subprocess.Popen(args, stdout=fp, close_fds=True) #启动一个子程序,用于将输出信息写到指定文件

    def _start_afl(self):
        '''
        start up a number of AFL instances to begin fuzzing
        '''

        # spin up the master AFL instance
        master = self._start_afl_instance() # the master fuzzer 启动了一个masterafl master是一个 Popen 对象
        self.procs.append(master)

        if self.afl_count > 1: #判断是否启动多个afl
            driller = self._start_afl_instance()
            self.procs.append(driller)

        # only spins up an AFL instances if afl_count > 1
        for _ in range(2, self.afl_count):
            slave = self._start_afl_instance()
            self.procs.append(slave)

    ### UTIL

    @staticmethod
    def _perform_env_checks():
        # check for afl sensitive settings
        with open("/proc/sys/kernel/core_pattern") as f:
            if not "core" in f.read():
                l.error("AFL Error: Pipe at the beginning of core_pattern")
                raise InstallError("execute 'echo core | sudo tee /proc/sys/kernel/core_pattern'")

        # This file is based on a driver not all systems use
        # http://unix.stackexchange.com/questions/153693/cant-use-userspace-cpufreq-governor-and-set-cpu-frequency
        # TODO: Perform similar performance check for other default drivers.
        if os.path.exists("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"):
            with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") as f:
                if not "performance" in f.read():
                    l.error("AFL Error: Suboptimal CPU scaling governor")
                    raise InstallError("execute 'cd /sys/devices/system/cpu; echo performance | sudo tee cpu*/cpufreq/scaling_governor'")

        # TODO: test, to be sure it doesn't mess things up
        with open("/proc/sys/kernel/sched_child_runs_first") as f:
            if not "1" in f.read():
                l.error("AFL Warning: We probably want the fork() children to run first")
                raise InstallError("execute 'echo 1 | sudo tee /proc/sys/kernel/sched_child_runs_first'")

    @staticmethod
    def _get_base():
        '''
        find the directory containing bin, there should always be a directory
        containing bin below base intially
        '''
        base = os.path.dirname(__file__)

        while not "bin" in os.listdir(base) and os.path.abspath(base) != "/":
            base = os.path.join(base, "..")

        if os.path.abspath(base) == "/":  
            raise InstallError("could not find afl install directory")

        return base

    def _export_library_path(self, p):
        '''
        export the correct library path for a given architecture
        '''
        path = None

        if self.library_path is None:
            directory = None
            if p.arch.qemu_name == "aarch64":
                directory = "arm64"
            if p.arch.qemu_name == "i386":
                directory = "i386"
            if p.arch.qemu_name == "mips":
                directory = "mips"
            if p.arch.qemu_name == "mipsel":
                directory = "mipsel"
            if p.arch.qemu_name == "ppc":
                directory = "powerpc"
            if p.arch.qemu_name == "arm":
                # some stuff qira uses to determine the which libs to use for arm
                with open(self.binary_path, "rb") as f: progdata = f.read(0x800)
                if "/lib/ld-linux.so.3" in progdata:
                    directory = "armel"
                elif "/lib/ld-linux-armhf.so.3" in progdata:
                    directory = "armhf"

            if directory is None:
                l.warning("architecture \"%s\" has no installed libraries", p.arch.qemu_name)
            else:
                path = os.path.join(self.afl_dir, "..", "fuzzer-libs", directory)
        else:
            path = self.library_path

        if path is not None:
            l.debug("exporting QEMU_LD_PREFIX of '%s'", path)
            os.environ['QEMU_LD_PREFIX'] = path
