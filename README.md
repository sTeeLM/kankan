# kankan
dedrm demo of XX, success rate 80.06%

# 使用方法
1. 通过download命令下载某看drm的的epub和coverpage
2. 通过list命令看看最大的是不是一个图片文件，否则失败
3. 如果最大文件是OEBPS/Images/coverpage.jpg，恭喜，可能能不花钱dedrm，否则花钱买电子书，并且通过web阅读器得到那个最大图片文件的明文
4. 尝试通过dedrm和analyse命令，利用最大的那个图片明文（可能是coverpage）和下载下来的epub，产生dedrm结果，如果使用了多个iv，依次找到对应图片明文并附加在-k之后
5. 反复尝试步骤4

注：如果你能忍受一些图片内容被截断，可以不用纠结获得最大内容图片

# 原理
1. 文件加密使用aes128-ctr
2. 加密用的iv epub所有文件相同或者被大量复用
3. 最大的内容文件往往是图片
4. 明文内容web可获取

# 建议解决方法
1. epub中每文件加密用不同iv
2. web reader中图片做缩放
3. 更换加密算法为cbc或者其它模式
