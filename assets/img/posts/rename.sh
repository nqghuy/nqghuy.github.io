#!/usr/bin/env bash

# Thư mục gốc chứa các thư mục con
ROOT_DIR="/home/nqghuy/Projects/My-web/assets/img/posts"

# Các phần mở rộng ảnh cần xử lý
extensions="png jpg jpeg webp gif bmp"

# Duyệt tất cả thư mục con
find "$ROOT_DIR" -type d | while read -r dir; do
    count=1

    for ext in $extensions; do
        for img in "$dir"/image."$ext"; do
            # Nếu file tồn tại
            if [[ -f "$img" ]]; then
                newname="$dir/image-$count.$ext"
                echo "Rename: $img → $newname"
                mv "$img" "$newname"
                ((count++))
            fi
        done
    done
done

