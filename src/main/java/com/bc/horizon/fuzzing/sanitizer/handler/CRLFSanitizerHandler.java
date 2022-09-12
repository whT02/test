package com.bc.horizon.fuzzing.sanitizer.handler;

import com.bc.horizon.fuzzing.sanitizer.annotation.Hook;
import com.bc.horizon.fuzzing.sanitizer.annotation.HookType;
import com.bc.horizon.fuzzing.sanitizer.annotation.Hooks;
import com.bc.horizon.fuzzing.sanitizer.model.Result;

import java.util.Arrays;

@Hooks(
        value = {
                @Hook(type = HookType.before, targetMethod = "<init>", targetClass = "java.net.URL")
                //@Hook(type = HookType.before, targetMethod = "openConnection", targetClass = "java.net.URL")
        }
)
public class CRLFSanitizerHandler implements ConstructorSanitizerHandler{

    @Override
    public Result handle(String className, String method, Object[] args, Integer methodLine, StackTraceElement[] stackTraceElements) {
        //example: String ATTACK = "http://www.baidu.com%0d%0aSet-cookie=crlf=true";
        if(args.length > 0){
            String url = (String) args[0];
            if (url.contains("%0d") || url.contains("%0a")|| url.contains("\r")|| url.contains("\n")) {
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
                        .exceptionDesc("初始化连接的URl连接中包含'%0a','%0d','\r'或'\n'字符串，Http报文头部正在被CRLF字符分割，可能存在CRLF注入漏洞，建议检查连接的URL！")
                        .requestParam(Arrays.toString(args))
                        .stackInfo(Arrays.toString(stackTraceElements))
                        .exceptionName("CRLF Injection")
                        .methodLine(methodLine)
                        .exceptionId("1")
                        .build();
            }
        }
        return Result.builder().needRecord(false).build();
    }
}
