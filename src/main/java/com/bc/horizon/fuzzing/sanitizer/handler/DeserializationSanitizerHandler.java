package com.bc.horizon.fuzzing.sanitizer.handler;

import com.bc.horizon.fuzzing.sanitizer.annotation.Hook;
import com.bc.horizon.fuzzing.sanitizer.annotation.HookType;
import com.bc.horizon.fuzzing.sanitizer.annotation.Hooks;
import com.bc.horizon.fuzzing.sanitizer.model.Result;

import java.io.ObjectStreamClass;
import java.lang.reflect.Method;
import java.util.Arrays;

@Hooks(
        value = {
                @Hook(type = HookType.after, targetMethod = "readObject", targetClass = "javax.io.ObjectInputStream"),
                @Hook(type = HookType.after, targetMethod = "readObjectOverride", targetClass = "javax.io.ObjectInputStream"),
                @Hook(type = HookType.after, targetMethod = "readUnshared", targetClass = "javax.io.ObjectInputStream")
        }
)

public class DeserializationSanitizerHandler implements SanitizerHandler{
    @Override
    public Result handle(Method method, Object[] args, Integer methodLine, StackTraceElement[] stackTraceElements) {
        if (args.length > 0){
            //TODO:确认ObjectInputStream.readObject的after hook的结果存储在args[]中的格式
            //ObjectStreamClass objectStreamClass = ObjectStreamClass.lookup((Class<?>) args[0]);
            String className = (String) args[0];
            String[] denyClasses = {"java.net.InetAddress",
                    "org.apache.commons.collections.Transformer",
                    "org.apache.commons.collections.functors.InvokerTransformer",
                    "org.apache.commons.collections.functors.InstantiateTransformer",
                    "org.apache.commons.collections4.functors.InvokerTransformer",
                    "org.apache.commons.collections4.functors.InstantiateTransformer",
                    "org.codehaus.groovy.runtime.ConvertedClosure",
                    "org.codehaus.groovy.runtime.MethodClosure",
                    "org.springframework.beans.factory.ObjectFactory",
                    "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
                    "org.apache.commons.fileupload",
                    "org.apache.commons.beanutils",
            };

            for (String denyClass : denyClasses) {
                if (className.startsWith(denyClass)) {
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
                            .exceptionDesc("反序列化类名中包含恶意第三方库类名，建议更新commons-collections等第三方库版本，并尽量使用白名单校验方式对外部反序列化输入数据进行校验！")
                            .requestParam(Arrays.toString(args))
                            .stackInfo(Arrays.toString(stackTraceElements))
                            .exceptionName("Deserialization")
                            .methodLine(methodLine)
                            .exceptionId("13")
                            .build();
                }
            }
        }
        return Result.builder().needRecord(true).build();
    }
}
