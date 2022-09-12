package com.bc.horizon.fuzzing.sanitizer.handler;

import com.bc.horizon.fuzzing.sanitizer.model.Result;

import java.lang.reflect.Method;

/**
 * <p>DESC: sanitizer处理程序的接口  所有处理程序均实现这个接口</p >
 * <p>DATE: 2022/6/27 0027</p >
 * <p>VERSION:1.0.0</p >
 * <p>@AUTHOR: DengC</p >
 */
public interface SanitizerHandler {

    /**
     * 处理程序
     *
     * @param method             方法信息
     * @param args               入参
     * @param methodLine         行号
     * @param stackTraceElements 堆栈信息
     * @return 处理结果
     */
    Result handle(Method method, Object[] args, Integer methodLine, StackTraceElement[] stackTraceElements);
}
