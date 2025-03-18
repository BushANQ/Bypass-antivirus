<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <link rel="icon" href="favicon.ico">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>杀软在线识别-渊龙Sec安全团队</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #4285f4;
            --primary-hover: #1a73e8;
            --primary-light: rgba(66, 133, 244, 0.1);
            --secondary-color: #34a853;
            --danger-color: #ea4335;
            --info-color: #fbbc05;
            --bg-color: #f5f7fa;
            --bg-card: #ffffff;
            --text-color: #333;
            --text-muted: #666;
            --border-color: #e0e0e0;
            --border-radius: 10px;
            --box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
            --transition: all 0.3s ease;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', 'Microsoft YaHei', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background-color: var(--bg-color);
            background-image: 
                radial-gradient(circle at 25% 10%, rgba(66, 133, 244, 0.05) 0%, transparent 20%),
                radial-gradient(circle at 75% 75%, rgba(66, 133, 244, 0.05) 0%, transparent 20%);
            color: var(--text-color);
            line-height: 1.6;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }
        
        .container {
            width: 90%;
            max-width: 1000px;
            margin: 30px auto;
            text-align: center;
        }
        
        header {
            text-align: center;
            margin-bottom: 30px;
            position: relative;
        }
        
        h1 {
            color: var(--primary-color);
            font-size: 2.8em;
            margin-bottom: 10px;
            font-weight: 600;
            position: relative;
            display: inline-block;
        }
        
        h1::after {
            content: "";
            position: absolute;
            bottom: -10px;
            left: 50%;
            transform: translateX(-50%);
            width: 60px;
            height: 3px;
            background: linear-gradient(90deg, transparent, var(--primary-color), transparent);
        }
        
        h3 {
            font-weight: 400;
            color: var(--text-muted);
            margin-top: 15px;
            font-size: 1rem;
        }
        
        a {
            color: var(--primary-color);
            text-decoration: none;
            transition: var(--transition);
        }
        
        a:hover {
            text-decoration: underline;
            color: var(--primary-hover);
        }
        
        .search-section {
            background-color: var(--bg-card);
            padding: 30px;
            border-radius: var(--border-radius);
            margin-bottom: 30px;
            border: 1px solid var(--border-color);
            box-shadow: var(--box-shadow);
            position: relative;
            overflow: hidden;
        }
        
        .search-section::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, transparent, var(--primary-color), transparent);
        }
        
        textarea {
            width: 100%;
            height: 200px;
            padding: 15px;
            font-size: 16px;
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius);
            resize: vertical;
            transition: var(--transition);
            font-family: 'Consolas', monospace;
            background-color: #f8f9fa;
            color: var(--text-color);
            box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        
        textarea:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(66, 133, 244, 0.2);
        }
        
        .command-container {
            display: flex;
            align-items: center;
            justify-content: center;
            margin-top: 20px;
            position: relative;
        }
        
        #commandInput {
            width: 250px;
            padding: 12px 15px;
            font-size: 15px;
            border: 1px solid var(--border-color);
            border-radius: var(--border-radius);
            text-align: center;
            background-color: #f5f5f5;
            font-family: 'Consolas', monospace;
            color: var(--text-color);
            transition: var(--transition);
        }
        
        #commandInput:focus {
            outline: none;
            border-color: var(--primary-color);
        }
        
        .button-group {
            margin-top: 25px;
            display: flex;
            justify-content: center;
            gap: 15px;
            flex-wrap: wrap;
        }
        
        button {
            padding: 12px 25px;
            font-size: 15px;
            border: none;
            border-radius: var(--border-radius);
            cursor: pointer;
            transition: var(--transition);
            font-weight: 500;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }
        
        button:focus {
            outline: none;
        }
        
        .submit-button {
            background-color: var(--primary-color);
            color: white;
        }
        
        .submit-button:hover {
            background-color: var(--primary-hover);
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
        }
        
        .clear-button {
            background-color: var(--danger-color);
            color: white;
        }
        
        .clear-button:hover {
            background-color: #d62516;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
        }
        
        .copy-button {
            background-color: var(--info-color);
            color: var(--text-color);
        }
        
        .copy-button:hover {
            background-color: #e8ae00;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
        }
        
        .results-section {
            background-color: var(--bg-card);
            padding: 30px;
            border-radius: var(--border-radius);
            border: 1px solid var(--border-color);
            box-shadow: var(--box-shadow);
            position: relative;
            overflow: hidden;
            margin-bottom: 30px;
        }
        
        .results-section::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, transparent, var(--secondary-color), transparent);
        }
        
        .results-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid var(--border-color);
        }
        
        .results-header h2 {
            font-size: 1.6em;
            font-weight: 600;
            color: var(--secondary-color);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .result {
            text-align: left;
            color: var(--text-color);
        }
        
        .result p {
            margin: 10px 0;
            padding: 12px;
            border-radius: 8px;
            background-color: #f8f9fa;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
            border-left: 3px solid var(--secondary-color);
        }
        
        .result p strong {
            color: var(--primary-color);
        }
        
        .empty-result {
            text-align: center;
            padding: 40px 20px;
            color: var(--text-muted);
            font-size: 1.1em;
        }
        
        .empty-result i {
            font-size: 3em;
            margin-bottom: 15px;
            color: var(--primary-color);
            opacity: 0.5;
        }
        
        .footer {
            margin-top: 20px;
            font-size: 14px;
            color: var(--text-muted);
            text-align: center;
        }
        
        .copy-notification {
            position: fixed;
            top: 20px;
            right: 20px;
            background-color: var(--secondary-color);
            color: white;
            padding: 10px 20px;
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow);
            opacity: 0;
            transform: translateY(-20px);
            transition: opacity 0.3s, transform 0.3s;
            z-index: 1000;
        }
        
        .copy-notification.show {
            opacity: 1;
            transform: translateY(0);
        }
        
        @media (max-width: 768px) {
            .container {
                width: 95%;
                padding: 15px;
            }
            
            h1 {
                font-size: 2.2em;
            }
            
            .search-section, .results-section {
                padding: 20px;
            }
            
            .button-group {
                flex-direction: column;
                gap: 10px;
            }
            
            button {
                width: 100%;
            }
            
            .results-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
        }
    </style>
    <script>
        function clearTextarea() {
            document.getElementById('user_input').value = '';
        }

        function copyToClipboard() {
            var copyText = document.getElementById("commandInput");
            copyText.select();
            copyText.setSelectionRange(0, 99999); // 对移动设备有用
            document.execCommand("copy");
            
            // 显示通知而不是alert
            const notification = document.createElement('div');
            notification.className = 'copy-notification';
            notification.textContent = '已复制: ' + copyText.value;
            document.body.appendChild(notification);
            
            // 触发重排以应用动画
            setTimeout(() => {
                notification.classList.add('show');
            }, 10);
            
            // 2秒后移除通知
            setTimeout(() => {
                notification.classList.remove('show');
                setTimeout(() => {
                    document.body.removeChild(notification);
                }, 300);
            }, 2000);
        }
    </script>
</head>
<body>
    <div class="container">
        <header>
            <h1>杀软在线识别-<a href="https://www.aabyss.cn">渊龙Sec安全团队</a></h1>
            <h3>如有漏报欢迎提交至我们的开源项目<br><a href="https://github.com/Aabyss-Team/Antivirus-Scan">https://github.com/Aabyss-Team/Antivirus-Scan</a></h3>
        </header>

<?php
// 初始化变量
$result = '';
$input = '';

// 处理 POST 请求
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $input = $_POST['user_input'] ?? '';

    // 按行拆分输入的内容
    $lines = explode("\n", $input);

    // 格式化处理：找到每行中的 " K " 和 " KB " 并换行处理
    $formattedLines = [];
    foreach ($lines as $line) {
        $line = trim($line);

        // 处理 " KB " 的格式化
        if (strpos($line, ' KB ') !== false) {
            $parts = explode('KB', $line);
            foreach ($parts as $key => $part) {
                $formattedLines[] = trim($part) . ($key < count($parts) - 1 ? 'KB' : '');
            }
        } 
        // 处理 " K " 的格式化
        elseif (strpos($line, ' K ') !== false) {
            $parts = explode('K', $line);
            foreach ($parts as $key => $part) {
                $formattedLines[] = trim($part) . ($key < count($parts) - 1 ? 'K' : '');
            }
        } else {
            $formattedLines[] = $line;
        }
    }

    // 重组格式化后的文本
    $formattedText = implode("\n", $formattedLines);

    // 从 JSON 文件读取数据
    $jsonData = file_get_contents('auto.json');
    $data = json_decode($jsonData, true);

    // 匹配处理
    $matches = [];
    foreach (explode("\n", $formattedText) as $line) {
        foreach ($data as $key => $value) {
            foreach ($value['processes'] as $process) {
                if (stripos($line, $process) === 0) { // 仅匹配每行的开头部分，且忽略大小写
                    // 如果软件名已存在，则添加到现有的进程列表中
                    if (!isset($matches[$key])) {
                        $matches[$key] = [
                            'url' => $value['url'],
                            'processes' => []
                        ];
                    }
                    $matches[$key]['processes'][] = htmlspecialchars($process);
                }
            }
        }
    }
    // 去重每个软件名对应的进程列表
    foreach ($matches as $key => $details) {
        $matches[$key]['processes'] = array_unique($details['processes']);
    }

    // 生成 HTML 显示结果
    if (count($matches) > 0) {
        foreach ($matches as $softwareName => $details) {
            $result .= "<p><strong>" . htmlspecialchars($softwareName) . ":</strong> " 
                        . implode(', ', $details['processes']) . " ==> <a href=\"" 
                        . htmlspecialchars($details['url']) . "\" target=\"_blank\">" 
                        . htmlspecialchars($details['url']) . "</a></p>";
        }
    } else {
        $result = "<p>未找到匹配的进程，如有漏报欢迎提交至我们的开源项目</br><a href=\"https://github.com/Aabyss-Team/Antivirus-Scan\">https://github.com/Aabyss-Team/Antivirus-Scan</a></p>";
    }
}
?>
        <!-- 表单 -->
        <section class="search-section">
            <form action="index.php" method="POST">
                <textarea name="user_input" id="user_input" placeholder="在此输入 tasklist /SVC 命令的执行结果..."><?php echo htmlspecialchars($input); ?></textarea>
                
                <div class="command-container">
                    <input type="text" id="commandInput" value="tasklist /SVC" readonly>
                </div>
                
                <div class="button-group">
                    <button type="submit" class="submit-button">
                        <i class="fas fa-search"></i> 提交分析
                    </button>
                    <button type="button" class="clear-button" onclick="clearTextarea()">
                        <i class="fas fa-trash-alt"></i> 清空内容
                    </button>
                    <button type="button" class="copy-button" onclick="copyToClipboard()">
                        <i class="fas fa-copy"></i> 复制命令
                    </button>
                </div>
            </form>
        </section>
        
        <!-- 结果显示区域 -->
        <?php if ($result !== ''): ?>
        <section class="results-section">
            <div class="results-header">
                <h2><i class="fas fa-shield-alt"></i> 分析结果</h2>
            </div>
            <div class="result">
                <?php echo $result; ?>
            </div>
        </section>
        <?php endif; ?>
        
        <div class="footer">
            <p>项目版本号 V1.7.4-2025.3</p>
        </div>
    </div>
</body>
</html>
