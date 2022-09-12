package com.bc.horizon.fuzzing.sanitizer.handler;

import com.bc.horizon.fuzzing.sanitizer.annotation.Hook;
import com.bc.horizon.fuzzing.sanitizer.annotation.HookType;
import com.bc.horizon.fuzzing.sanitizer.annotation.Hooks;
import com.bc.horizon.fuzzing.sanitizer.model.Result;

import java.lang.reflect.Method;
import java.util.Arrays;

@Hooks(
        value = {
                @Hook(type = HookType.before, targetMethod = "lookup", targetClass = "javax.naming.InitialContext"),
                @Hook(type = HookType.before, targetMethod = "lookupLink", targetClass = "javax.naming.InitialContext")
        }
)
public class NamingContextLookupSanitizerHandler implements SanitizerHandler{

    @Override
    public Result handle(Method method, Object[] args, Integer methodLine, StackTraceElement[] stackTraceElements) {

        if(args.length > 0){
            String name = (String) args[0];
            //定义恶意远程URL对象
            String LDAP_MARKER = "ldap";
            String RMI_MARKER = "rmi";
            if (name.contains(RMI_MARKER) || name.contains(LDAP_MARKER)){
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
                        .exceptionDesc("JNDI远程访问参数中可能存在恶意LDAP或RMI对象，会导致远程代码执行或目录信息泄露，建议使用JNDI查找时对远程URL对象设置白名单！")
                        .requestParam(Arrays.toString(args))
                        .stackInfo(Arrays.toString(stackTraceElements))
                        .exceptionName("JNDI Injection")
                        .methodLine(methodLine)
                        .exceptionId("3")
                        .build();
            }
        }
        System.out.println("methodLine=" + methodLine);
        System.out.println("methodInfo=" + method);
        System.out.println("args=" + Arrays.toString(args));
        return Result.builder().needRecord(true).build();
    }
}
