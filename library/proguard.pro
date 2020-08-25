# 代码混淆压缩比，在0~7之间，默认为5，一般不需要更改
-optimizationpasses 5
# 混淆时不适用大小写混合，混淆后的类名为小写
-dontusemixedcaseclassnames
# 指定不去忽略非公共的库的类
-dontskipnonpubliclibraryclasses
# 指定不去忽略非公共的库的类的成员
-dontskipnonpubliclibraryclassmembers
# 不做优化（变更代码实现逻辑）
-dontoptimize
# 不做预校验，preverify是proguard的4个步骤之一，android不需要做预校验，去除这一步可以加快混淆速度
# -dontpreverify
# 有了verbose这句话，混淆后就会生成映射文件
# -verbose
# 指定混淆时采用的算法，后面的参数是一个过滤器
-optimizations !code/simplification/arithmetic,!code/simplification/cast,!field/*,!class/merging/*,!code/allocation/variable

-keepattributes Exceptions,InnerClasses,Signature,Deprecated,SourceFile,LineNumberTable,*Annotation*,EnclosingMethod

-keepparameternames

-ignorewarnings

-keep class LICENSE {*;}

#这里添加你不需要混淆的类
-keep class net.yiim.yismcore.YiSMCore {
    public *;
}

-keep enum net.yiim.yismcore.YiCryptoErrorCode {*;}

-keep class net.yiim.yismcore.YiCryptoException {
    public *;
}

-keep class net.yiim.yismcore.YiCryptoKey {
    public *;
}