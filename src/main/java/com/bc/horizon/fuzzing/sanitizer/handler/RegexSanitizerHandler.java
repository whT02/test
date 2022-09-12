package com.bc.horizon.fuzzing.sanitizer.handler;

import com.bc.horizon.fuzzing.sanitizer.annotation.Hook;
import com.bc.horizon.fuzzing.sanitizer.annotation.HookType;
import com.bc.horizon.fuzzing.sanitizer.annotation.Hooks;
import com.bc.horizon.fuzzing.sanitizer.model.Result;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.regex.Pattern;

@Hook(type = HookType.before, targetMethod = "compile", targetClass = "java.util.regex.Pattern")
public class RegexSanitizerHandler implements SanitizerHandler {
    @Override
    public Result handle(Method method, Object[] args, Integer methodLine, StackTraceElement[] stackTraceElements) {
        if(args.length > 0){
            String CANON_EQ_ALMOST_EXPLOIT = "aaaaa";
            String pattern = (String) args[0];
            if (args.length > 1) {
                Integer flag = (Integer) args[1];
                if (flag == 128 && pattern != null) {
                    if (pattern.contains(CANON_EQ_ALMOST_EXPLOIT)) {

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
                                .exceptionDesc("当Pattern.compile 与 Pattern.CANON_EQ 标志一起使用时，每次注入正则表达式都可能导致任意大的内存分配，造成性能损耗，建议禁用Pattern.CANON_EQ标志！")
                                .requestParam(Arrays.toString(args))
                                .stackInfo(Arrays.toString(stackTraceElements))
                                .exceptionName("RegexInjection")
                                .methodLine(methodLine)
                                .exceptionId("6")
                                .build();
                    }
                }
            }
        }
        return Result.builder().needRecord(false).build();
    }
}
