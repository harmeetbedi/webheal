package org.webheal.util;

import org.apache.log4j.Logger;

public class Logable
{
    public Logger log() {
        return Logger.getLogger(getClass());
    }
    public Logger syncLog() {
        return Logger.getLogger("sync."+getClass().getSimpleName());
    }
    public static Logger syncLog(Class<?> cls) {
        return Logger.getLogger("sync."+cls.getSimpleName());
    }
    public static Logger sqlLog(Class<?> cls) {
        return Logger.getLogger("sql."+cls.getSimpleName());
    }
    public static Logger statLog(Class<?> cls) {
        return Logger.getLogger("stat."+cls.getSimpleName());
    }
}
