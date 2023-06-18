import io
import matplotlib.pyplot as plt
from flask import Flask
from flask import render_template  # 渲染
import base64

app = Flask(__name__)


@app.route('/')  # 主页地址,“装饰器”
def news():
    the_news = {
        'XXX1': '1',
        'XXX2': '2',
        'XXX3': '3',
        'XXX4': '4',
    }
    context = {
        'title': '新闻',
        'the_news': the_news,
    }
    img = io.BytesIO()
    y = [1, 2, 3, 4, 5]
    x = [0, 2, 1, 3, 4]
    plt.plot(x, y)
    plt.savefig(img, format='png', dpi=75)
    img.seek(0)
    plot_url = base64.b64encode(img.getvalue()).decode()
    return render_template('index.html', context=context, plot_url=plot_url)  # 把index.html文件读进来，再交给浏览器


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8083)  # 127.0.0.1 回路 自己返回自己
