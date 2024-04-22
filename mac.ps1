Import-Module DhcpServer

function Format-MacAddress {
  while ($true) {
    $macInput = Read-Host "请输入MAC地址 (支持不带分隔符、分隔符-和:)"
    $macAddress = $macInput.ToUpper() -replace '\s|-|:','' 
    if ($macAddress.Length -eq 12 -and $macAddress -cmatch '^[0-9A-F]+$') {
      $startIndex = 0
      while ($startIndex -lt $macAddress.Length) {
        $macAddress = $macAddress.Insert($startIndex, '-')
        $startIndex += 3
      }
      return $macAddress.Substring(1) 
    } else {
      Write-Host "错误：MAC地址无效。请任意键重新输入。" 
      [System.Console]::ReadKey($true) 
    }
  }
}

function Get-SelectedDhcpScope {
  $scopes = Get-DhcpServerv4Scope
  Write-Host "请选择一个DHCP作用域:"
  $i = 0
  foreach ($scope in $scopes) {
    $i++
    Write-Host "$i. $($scope.ScopeId)"
  }
  $maxChoice = [math]::Max(1, $scopes.Count)
  while ($true) {
    $choice = Read-Host "输入序号"
    if ($choice -as [int] -and $choice -ge 1 -and $choice -le $maxChoice) {
      return $scopes[$choice - 1]
    } else {
      Write-Host "错误：请输入有效的序号 (1-$maxChoice)。" 
    }
  }
}

function Get-ReservationAndFilterByMac ($macAddress, $selectedScope) {
  $reservations = Get-DhcpServerv4Reservation -ScopeId $selectedScope.ScopeId
  $reservation = $reservations | Where-Object { $_.ClientId -eq $macAddress }
  $filters = Get-DhcpServerv4Filter -List Allow
  $filter = $filters | Where-Object { $_.MacAddress -eq $macAddress }
  return $reservation, $filter 
}

function Test-MacAddressExists {
  param(
    [Parameter(Mandatory = $true)]
    [string] $MacAddress,
    [Parameter(Mandatory = $true)]
    [object] $SelectedScope
  )
  $reservation, $filter = Get-ReservationAndFilterByMac $MacAddress $SelectedScope
  if (-not $reservation -and -not $filter) {
    return $false
  } else {
    return $true 
  }
}

while ($true) {
  $choice = Read-Host "请选择功能:
1. 添加MAC地址
2. 删除MAC地址
3. 查询MAC地址
4. 通过名称模糊查找
5. 修改保留IP

输入序号"
  if ($choice -as [int] -and $choice -ge 1 -and $choice -le 5) {
    break 
  } else {
    Write-Host "错误：请输入有效的序号 (1-5)。"
  }
}

switch ($choice) {
  1 {
    $macAddress = Format-MacAddress
    $name = Read-Host "请输入名称"
    $selectedScope = Get-SelectedDhcpScope
    if (Test-MacAddressExists -MacAddress $macAddress -SelectedScope $selectedScope) { 
      $reservation, $filter = Get-ReservationAndFilterByMac $macAddress $selectedScope
      if ($reservation -and $reservation.IPAddress) { 
        Write-Host "注意：MAC地址 $macAddress 已存在预留项。"
        Write-Host "现有预留信息："
        Write-Host "IP地址: $($reservation.IPAddress)"
        Write-Host "名称: $($reservation.Description)"
        $choice = Read-Host "是否要继续添加并覆盖现有预留? (y/n)"
        if ($choice -ne 'y') {
          Write-Host "操作已取消。"
          break 
        }
        Remove-DhcpServerv4Reservation -IPAddress $reservation.IPAddress 
      } else { 
        Write-Host "注意：MAC地址 $macAddress 已存在于筛选器列表中，但没有预留项。" 
      }
      if ($filter) {
        Remove-DhcpServerv4Filter -MacAddress $macAddress 
      }
    } 
    $freeIp = $selectedScope | Get-DhcpServerv4FreeIPAddress
    if (-not $filter) { 
      Add-DhcpServerv4Filter -List Allow -MacAddress $macAddress -Description $name
    }
    Add-DhcpServerv4Reservation -ScopeId $selectedScope.ScopeId -IPAddress $freeIp -ClientId $macAddress -Description $name
    Write-Host "分配的IP地址: $freeIp"
    Write-Host "MAC地址: $macAddress"
    Write-Host "名称: $name"
}
  2 {
    $macAddress = Format-MacAddress
    $selectedScope = Get-SelectedDhcpScope
    if (-not (Test-MacAddressExists -MacAddress $macAddress -SelectedScope $selectedScope)) { 
      Write-Host "错误：未找到 MAC 地址为 $macAddress 的预留项或筛选器。"
    } else {
      $reservation, $filter = Get-ReservationAndFilterByMac $macAddress $selectedScope
      if ($reservation) {
        Remove-DhcpServerv4Reservation -IPAddress $reservation.IPAddress 
        Write-Host "已成功删除 MAC 地址为 $macAddress 的预留项。"
      }
      if ($filter) {
        Remove-DhcpServerv4Filter -MacAddress $macAddress 
        Write-Host "已成功删除 MAC 地址为 $macAddress 的筛选器。"
      }
    }
  }
  3 {
    $macAddress = Format-MacAddress
    $selectedScope = Get-SelectedDhcpScope
    if (-not (Test-MacAddressExists -MacAddress $macAddress -SelectedScope $selectedScope)) { 
      Write-Host "错误：未找到 MAC 地址为 $macAddress 的预留项或筛选器。"
    } else { 
      $reservation, $filter = Get-ReservationAndFilterByMac $macAddress $selectedScope
      if ($reservation -and $filter) {
        Write-Host "MAC地址: $($reservation.ClientId)"
        Write-Host "IP地址: $($reservation.IPAddress)"
        Write-Host "名称: $($reservation.Description)"
        Write-Host "MAC地址 $macAddress 同时在预留项和允许筛选器列表中"
      } elseif ($reservation) {
        Write-Host "MAC地址: $($reservation.ClientId)"
        Write-Host "IP地址: $($reservation.IPAddress)"
        Write-Host "名称: $($reservation.Description)"
        Write-Host "MAC地址 $macAddress 只在预留项中"
      } elseif ($filter) {
        Write-Host "MAC地址 $macAddress 在允许筛选器列表中"
      } 
    }
  }
  4 {
    $keyword = Read-Host "请输入要搜索的关键词"
    $filters = Get-DhcpServerv4Filter
    $filters | Where-Object { $_.Description -match $keyword -or $_.MacAddress -match $keyword } | ForEach-Object { Write-Output $_ }
  }
  5 {
    $macAddress = Format-MacAddress
    $selectedScope = Get-SelectedDhcpScope
    if (-not (Test-MacAddressExists -MacAddress $macAddress -SelectedScope $selectedScope)) { 
      Write-Host "错误：未找到 MAC 地址为 $macAddress 的预留项。"
    } else {
      $reservations = Get-DhcpServerv4Reservation -ScopeId $selectedScope.ScopeId
      $reservation = $reservations | Where-Object { $_.ClientId -eq $macAddress }

      while ($true) {
        $ipChoice = Read-Host "请选择IP地址获取方式: 1. 输入IP地址 2. 自动获取可用IP地址 输入序号"
        if ($ipChoice -as [int] -and $ipChoice -ge 1 -and $ipChoice -le 2) {
          break 
        } else {
          Write-Host "错误：请输入有效的序号 (1 或 2)。"
        }
      }

      if ($ipChoice -eq 1) { $newIp = Read-Host "请输入新的IP地址" } 
      else { $newIp = $selectedScope | Get-DhcpServerv4FreeIPAddress }
      Remove-DhcpServerv4Reservation -IPAddress $reservation.IPAddress
      Add-DhcpServerv4Reservation -ScopeId $selectedScope.ScopeId -IPAddress $newIp -ClientId $macAddress -Description $reservation.Description
      Write-Host "已成功将MAC地址 $macAddress 的IP地址修改为 $newIp"
    }
  }
}  

[System.Console]::Write("按任意键退出...")
[void][System.Console]::ReadKey(1)
