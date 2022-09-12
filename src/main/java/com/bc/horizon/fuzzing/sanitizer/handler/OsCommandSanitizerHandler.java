package com.bc.horizon.fuzzing.sanitizer.handler;

import com.bc.horizon.fuzzing.sanitizer.annotation.Hook;
import com.bc.horizon.fuzzing.sanitizer.annotation.HookType;
import com.bc.horizon.fuzzing.sanitizer.annotation.Hooks;
import com.bc.horizon.fuzzing.sanitizer.model.Result;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Objects;

@Hooks(
        value = {
                @Hook(type = HookType.before, targetMethod = "start", targetClass = "java.lang.ProcessImpl"),
                @Hook(type = HookType.before, targetMethod = "start", targetClass = "java.lang.ProcessBuilder"),
                @Hook(type = HookType.before, targetMethod = "exec", targetClass = "java.lang.Runtime")
        }
)
public class OsCommandSanitizerHandler implements SanitizerHandler{
    @Override
    public Result handle(Method method, Object[] args, Integer methodLine, StackTraceElement[] stackTraceElements) {
        if(args.length > 0){
            String cmd = (String) args[0];
            if(cmd != null){
                if(cmd.matches("^ls|pwd|passwd|tree|lstree|chmod|cp|rm|mv|touch|sudo|exit|shutdown|htop|echo|apt|ps|history|neofetch$")){

                    if (stackTraceElements != null) {
                        for (StackTraceElement stackElement : stackTraceElements) {
                            System.out.println("at " + stackElement.getClassName()
                                    + stackElement.getMethodName() + "(" + stackElement.getFileName() +
                                    ":" + stackElement.getLineNumber() + ")");
                        }
                    }

                    return Result.builder()
                            .needRecord(true)
                            .exceptionMethod(method.getName())
                            .exceptionClass(method.getDeclaringClass().getName())
                            .exceptionDesc("命令执行方法的外部可控参数中存在恶意命令注入缺陷，建议对外部输入命令实施过滤或者设置命令输入白名单！")
                            .requestParam(Arrays.toString(args))
                            .stackInfo(Arrays.toString(stackTraceElements))
                            .exceptionName("OSCommand Injection")
                            .methodLine(methodLine)
                            .exceptionId("4")
                            .build();
                }
            }
        }
        return Result.builder().needRecord(false).build();
    }
}
