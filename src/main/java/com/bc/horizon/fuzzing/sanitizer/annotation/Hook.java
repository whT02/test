package com.bc.horizon.fuzzing.sanitizer.annotation;

import java.lang.annotation.*;

/**
 * <p>DESC: </p >
 * <p>DATE: 2022/6/27 0027</p >
 * <p>VERSION:1.0.0</p >
 * <p>@AUTHOR: DengC</p >
 */
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Hook {
    /**
     * @see HookType
     * @return  hook方式
     */
    HookType[] type();

    /**
     * 被hook的   类全限定名称
     * @return 类全限定名称
     */
    String targetClass();

    /**
     * 被hook的方法名称
     * @return 方法名称
     */
    String targetMethod();


}
