package com.bc.horizon.fuzzing.sanitizer.handler;

import com.bc.horizon.fuzzing.sanitizer.annotation.Hook;
import com.bc.horizon.fuzzing.sanitizer.annotation.HookType;
import com.bc.horizon.fuzzing.sanitizer.model.Result;

import java.lang.reflect.Method;
import java.util.Arrays;

@Hook(type = HookType.before, targetMethod = "<init>", targetClass = "java.io.File")
public class PathTraverseSanitizerHandle implements ConstructorSanitizerHandler{

    @Override
    public Result handle(String className, String method, Object[] args, Integer methodLine, StackTraceElement[] stackTraceElements) {
        if(args.length > 0){
            String pathname = (String) args[0];
            if (pathname.contains("../")||pathname.contains("~")){
                if (stackTraceElements != null) {
                    for (StackTraceElement stackElement : stackTraceElements) {
                        System.out.println("at " + stackElement.getClassName()
                                + stackElement.getMethodName() + "(" + stackElement.getFileName() +
                                ":" + stackElement.getLineNumber() + ")");
                    }
                }

                return Result.builder()
                        .needRecord(true)
                        .exceptionMethod(method)
                        .exceptionClass(className)
                        .exceptionDesc("初始化文件名中包含特殊字符('../'或'~')，正在越权访问一些目录文件，可能存在路径遍历缺陷，建议对特殊字符串进行过滤，并查看文件是否为恶意文件！")
                        .requestParam(Arrays.toString(args))
                        .stackInfo(Arrays.toString(stackTraceElements))
                        .exceptionName("PathTraverse")
                        .methodLine(methodLine)
                        .exceptionId("5")
                        .build();
            }
        }
        return Result.builder().needRecord(false).build();
    }
}
