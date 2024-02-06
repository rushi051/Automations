import logging

def loghandlers(logger_name,fileloc,signal="disable",conLevel=logging.INFO):
        """
        Author:ss403v:Saurabh Sharma:saurabh.sharma1@amdocs.com
        Generic logging module
        Initially made for jvmbounce package
        Adding file logger and console logger settings
        Usage : import log
        Usage : log.loghandlers("absolute path of file",signal,conLevel)
        if signal is enable then it will also show file contents
        on console screen
        conLevel is used to enable type of level to be used for console
        loggin
        """
        if conLevel != logging.INFO:
                conLevel=conLevel.lower()
        if conLevel == "debug":
                conLevel=logging.DEBUG
        elif conLevel == "error":
                conLevel=logging.ERROR
        elif conLevel == "critical":
                conLevel=logging.CRITICAL
        elif conLevel == "warn":
                conLevel=logging.WARN
        else:
                conLevel=logging.INFO
        logger=logging.getLogger(logger_name)
        formatter=logging.Formatter("%(asctime)s %(filename)s:%(funcName)s:%(lineno)d |%(levelname)s| %(message)s")
        fileHandler=logging.FileHandler(fileloc,mode="w")
        fileHandler.setFormatter(formatter)
        fileHandler.setLevel(logging.DEBUG)
        logger.addHandler(fileHandler)
        if signal == "enable":
                conlogger=logging.StreamHandler()
                conlogger.setLevel(conLevel)
                conlogger.setFormatter(logging.Formatter('[%(levelname)s]  %(message)s'))
                logger.addHandler(conlogger)
        logger.setLevel(logging.DEBUG)
