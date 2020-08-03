# kankan
dedrm of XX, success rate 80.06%
# 使用方法
1）下载某看drm的的epub（通过android客户端）
2）通过工具的list命令，获得大小最大的文件，一般是内容配图。。。。，如果不是配图，dedrm失败T——T
3）在某看web版阅读器上找到这个图片并下载（明文）
4）通过工具的analyse命令，输入明文图片和对应epub中加密图片路径，如果能看到明文打印，成功！
5）通过工具的decrypt命令，输入明文图片和对应epub中加密图片路径，job done！
# 原理
内容加密per文件使用aes128-ctr，且所有文件使用一样的key和iv。。。。
