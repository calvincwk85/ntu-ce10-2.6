provider "aws" {
  region = "ap-southeast-1"  # Replace with your preferred AWS region
}

resource "aws_dynamodb_table" "cal-bookinventory" {
  name         = "cal-bookinventory"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "ISBN"
  range_key    = "Genre"

  attribute {
    name = "ISBN"
    type = "S"
  }

  attribute {
    name = "Genre"
    type = "S"
  }
}

resource "aws_iam_policy" "cal-dynamodb-read-1" {
  name        = "cal-dynamodb-read-1"
  description = "Allows read and list actions on DynamoDB"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["dynamodb:List*", "dynamodb:GetItem", "dynamodb:Scan", "dynamodb:Query"]
        Resource = "arn:aws:dynamodb:ap-southeast-1:255945442255:table/cal-bookinventory"
      }
    ]
  })
}

resource "aws_iam_role" "cal-dynamodb-read-role-1" {
  name = "cal-dynamodb-read-role-1"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach-policy" {
  role       = aws_iam_role.cal-dynamodb-read-role-1.name
  policy_arn = aws_iam_policy.cal-dynamodb-read-1.arn
}

resource "aws_iam_instance_profile" "cal-dynamodb-read-role-1" {
  name = "cal-dynamodb-read-role-1"
  role = aws_iam_role.cal-dynamodb-read-role-1.name
}

resource "aws_instance" "ec2" {
  ami           = "ami-0afc7fe9be84307e4"  # Replace with a valid AMI ID
  instance_type = "t2.micro"
  subnet_id                   = "subnet-0732248c94175c7ea"  #Public Subnet ID, e.g. subnet-xxxxxxxxxxx
  associate_public_ip_address = true
  key_name                    = "c2.5" #Change to your keyname, e.g. jazeel-key-pair
  vpc_security_group_ids = [aws_security_group.allow_ssh.id]
 
  tags = {
    Name = "cal-ec2"    #Prefix your own name, e.g. jazeel-ec2
  }

  iam_instance_profile = aws_iam_role.cal-dynamodb-read-role-1.name
}

resource "aws_security_group" "allow_ssh" {
  name        = "cal-security-group" #Security group name, e.g. jazeel-terraform-security-group
  description = "Allow SSH inbound"
  vpc_id      = "vpc-0f00a5f883f248f68"  #VPC ID (Same VPC as your EC2 subnet above), E.g. vpc-xxxxxxx
}

resource "aws_vpc_security_group_ingress_rule" "allow_tls_ipv4" {
  security_group_id = aws_security_group.allow_ssh.id
  cidr_ipv4         = "0.0.0.0/0"  
  from_port         = 22
  ip_protocol       = "tcp"
  to_port           = 22
}
