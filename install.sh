#!/bin/bash

echo "Installing Kosty - AWS Cost Optimization Tool..."

# Install dependencies
pip install -r requirements.txt

# Install the package in development mode
pip install -e .

echo "Installation complete!"
echo ""
echo "Usage examples:"
echo "  kosty ebs find-orphan"
echo "  kosty --organization lb no-target"
echo "  kosty --region us-west-2 ec2 find-idle --days 14"
echo ""
echo "For help: kosty --help"