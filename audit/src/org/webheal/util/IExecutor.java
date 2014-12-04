package org.webheal.util;



public interface IExecutor<X,Y>
{
    public Y execute(X param) throws Exception;
}
