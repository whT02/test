package com.bc.horizon.fuzzing.sanitizer.handler;

import com.bc.horizon.fuzzing.sanitizer.annotation.Hook;
import com.bc.horizon.fuzzing.sanitizer.annotation.HookType;
import com.bc.horizon.fuzzing.sanitizer.annotation.Hooks;
import com.bc.horizon.fuzzing.sanitizer.model.Result;

import java.lang.reflect.Method;
import java.util.Arrays;

@Hooks(
        value = {
                @Hook(type = HookType.before, targetMethod = "forName", targetClass = "java.lang.Class"),
                @Hook(type = HookType.before, targetMethod = "loadClass", targetClass = "java.lang.ClassLoader"),
                @Hook(type = HookType.before, targetMethod = "load", targetClass = "java.lang.System"),
                @Hook(type = HookType.before, targetMethod = "loadLibrary", targetClass = "java.lang.System"),
                @Hook(type = HookType.before, targetMethod = "mapLibraryName", targetClass = "java.lang.System"),
                @Hook(type = HookType.before, targetMethod = "load", targetClass = "java.lang.Runtime"),
                @Hook(type = HookType.before, targetMethod = "loadLibrary", targetClass = "java.lang.Runtime"),
                @Hook(type = HookType.before, targetMethod = "findLibrary", targetClass = "java.lang.ClassLoader")
        }
)
public class ReflectiveCallSanitizerHandler implements SanitizerHandler {
    @Override
    public Result handle(Method method, Object[] args, Integer methodLine, StackTraceElement[] stackTraceElements) {

        if (args.length > 0){
            String classname = (String) args[0];
            String attack = "java.lang.class";
            if (classname.contains(attack)){
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
                        .exceptionDesc("????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????")
                        .requestParam(Arrays.toString(args))
                        .stackInfo(Arrays.toString(stackTraceElements))
                        .exceptionName("Remote Code Injection")
                        .methodLine(methodLine)
                        .exceptionId("7")
                        .build();
            }
        }
        return Result.builder().needRecord(false).build();
    }
}
