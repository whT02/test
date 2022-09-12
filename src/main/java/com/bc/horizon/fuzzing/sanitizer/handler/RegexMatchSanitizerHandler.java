package com.bc.horizon.fuzzing.sanitizer.handler;

import com.bc.horizon.fuzzing.sanitizer.annotation.Hook;
import com.bc.horizon.fuzzing.sanitizer.annotation.HookType;
import com.bc.horizon.fuzzing.sanitizer.annotation.Hooks;
import com.bc.horizon.fuzzing.sanitizer.model.Result;

import java.lang.reflect.Method;
import java.util.Arrays;


@Hook(type = HookType.before, targetMethod = "matches", targetClass = "java.util.regex.Pattern")
public class RegexMatchSanitizerHandler implements SanitizerHandler{

    @Override
    public Result handle(Method method, Object[] args, Integer methodLine, StackTraceElement[] stackTraceElements) {
        if(args.length > 0){
            String pattern = (String) args[0];
            String FORCE_PATTERN_SYNTAX_EXCEPTION_PATTERN = "\\E]\\E]]]]]]";

            if(pattern.contains(FORCE_PATTERN_SYNTAX_EXCEPTION_PATTERN)){
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
                        .exceptionDesc("正则表达式中包含未转义的不受信任的输入，可能会导致大量占用CPU，建议检查Pattern.match方法中的参数!")
                        .requestParam(Arrays.toString(args))
                        .stackInfo(Arrays.toString(stackTraceElements))
                        .exceptionName("RegexInjection")
                        .methodLine(methodLine)
                        .exceptionId("6")
                        .build();
            }
        }

        return Result.builder().needRecord(false).build();
    }
}
