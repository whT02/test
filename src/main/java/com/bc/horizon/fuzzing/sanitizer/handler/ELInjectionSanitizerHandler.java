package com.bc.horizon.fuzzing.sanitizer.handler;

import com.bc.horizon.fuzzing.sanitizer.annotation.Hook;
import com.bc.horizon.fuzzing.sanitizer.annotation.HookType;
import com.bc.horizon.fuzzing.sanitizer.annotation.Hooks;
import com.bc.horizon.fuzzing.sanitizer.model.Result;

import java.lang.reflect.Method;
import java.util.Arrays;

@Hooks(
        value = {
                @Hook(type = HookType.before, targetMethod = "createValueExpression", targetClass = "javax.el.ExpressionFactory"),
                @Hook(type = HookType.before, targetMethod = "createMethodExpression", targetClass = "javax.el.ExpressionFactory"),
                @Hook(type = HookType.before, targetMethod = "buildConstraintViolationWithTemplate", targetClass = "javax.validation.ConstraintValidatorContext"),
        }
)
public class ELInjectionSanitizerHandler implements SanitizerHandler{
    @Override
    public Result handle(Method method, Object[] args, Integer methodLine, StackTraceElement[] stackTraceElements) {
        System.out.println("method=" + method); //测试是否触发到目标方法

        String EXPRESSION_LANGUAGE_ATTACK = "${''.getClass().forName('java.lang.Runtime').newInstance()}";
        if (args.length > 0){
            String expression = (String) args[1];
            if (expression.contains(EXPRESSION_LANGUAGE_ATTACK)){
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
                        .exceptionDesc("用户可控输入的EL表达式中可能存在远程代码执行的风险，建议对外部输入的EL表达式实施过滤和监测！")
                        .requestParam(Arrays.toString(args))
                        .stackInfo(Arrays.toString(stackTraceElements))
                        .exceptionName("Expression Language Injection")
                        .methodLine(methodLine)
                        .exceptionId("8")
                        .build();
            }
        }
        return Result.builder().needRecord(false).build();
    }
}
