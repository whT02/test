package com.bc.horizon.fuzzing.sanitizer.handler;

import com.bc.horizon.fuzzing.sanitizer.annotation.Hook;
import com.bc.horizon.fuzzing.sanitizer.annotation.HookType;
import com.bc.horizon.fuzzing.sanitizer.annotation.Hooks;
import com.bc.horizon.fuzzing.sanitizer.model.Result;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;


@Hooks(
        value = {
                @Hook(type = HookType.before, targetMethod = "search", targetClass = "javax.naming.directory.DirContext"),
                @Hook(type = HookType.before, targetMethod = "search", targetClass = "javax.naming.directory.InitialDirContext")
        }
)

public class LdapSanitizerHandler implements SanitizerHandler{

    @Override
    public Result handle(Method method, Object[] args, Integer methodLine, StackTraceElement[] stackTraceElements) {

        if(args.length > 0){
            String name = (String) args[0];
            ArrayList<String> list = new ArrayList<>();
            //查询中要转义的字符
            String FILTER_CHARACTERS = "&、！、|、=、<、>、,、+、-、”、’、;、（、）、*、NUL、/";
            String[] result = FILTER_CHARACTERS.split("、");

            for (String s : result) {
                list.add(String.valueOf(name.contains(s)));
            }
            if(list.contains("true")){
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
                        .exceptionDesc("Ldap查询参数中包含特殊字符，可能存在Ldap恶意注入导致信息泄露，建议对特殊字符实现反斜杠转义处理！")
                        .requestParam(Arrays.toString(args))
                        .stackInfo(Arrays.toString(stackTraceElements))
                        .exceptionName("LDAP Injection")
                        .methodLine(methodLine)
                        .exceptionId("2")
                        .build();
            }
        }
        return Result.builder().needRecord(false).build();
    }
}
