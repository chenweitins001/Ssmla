package com.xiaohua.mybatisdemo.Util;

import java.util.Locale;

public class localeDemo {

    public static void main(String[] args) {
        System.out.println("aaa");

        //获取安装系统里选择的语言
        System.out.println(Locale.getDefault());

        System.out.println(Locale.CHINA);
        System.out.println(Locale.US);//美国
        System.out.println(Locale.JAPAN);//日本


    }
}
